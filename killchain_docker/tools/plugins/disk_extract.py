"""disk.extract — bounded durable extraction from disk images."""

from __future__ import annotations
import re
import shlex
from typing import Any
from killchain_docker.state.domain import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command

_PARTITION_MARKER = "__KILLCHAIN_DISK_EXTRACT_PARTITION__"
_ENTRY_MARKER = "__KILLCHAIN_DISK_EXTRACT_ENTRY__"
_FILE_MARKER = "__KILLCHAIN_DISK_EXTRACT_FILE__"
_SKIP_MARKER = "__KILLCHAIN_DISK_EXTRACT_SKIP__"
_ERROR_MARKER = "__KILLCHAIN_DISK_EXTRACT_ERROR__"
_SUMMARY_MARKER = "__KILLCHAIN_DISK_EXTRACT_SUMMARY__"
_DEFAULT_MAX_FILES = 80
_DEFAULT_MAX_EXTRACT_MB = 96
_DISK_EXTRACT_PY = '\nimport hashlib\nimport mmap\nimport os\nimport re\nimport shutil\nimport subprocess\nimport sys\nimport zipfile\nfrom pathlib import Path\n\nPARTITION = "__KILLCHAIN_DISK_EXTRACT_PARTITION__"\nENTRY = "__KILLCHAIN_DISK_EXTRACT_ENTRY__"\nFILE = "__KILLCHAIN_DISK_EXTRACT_FILE__"\nSKIP = "__KILLCHAIN_DISK_EXTRACT_SKIP__"\nERROR = "__KILLCHAIN_DISK_EXTRACT_ERROR__"\nSUMMARY = "__KILLCHAIN_DISK_EXTRACT_SUMMARY__"\n\ndef clean(value):\n    return str(value).replace("\\t", " ").replace("\\n", " ")[:240]\n\ndef safe_part(value):\n    out = re.sub(r"[^A-Za-z0-9_.@%+=,-]+", "_", str(value).strip())\n    return out.strip("._")[:80] or "file"\n\ndef safe_relpath(value):\n    text = str(value).replace("\\\\", "/").strip().strip("/")\n    parts = []\n    for part in text.split("/"):\n        if not part or part in {".", ".."}:\n            continue\n        parts.append(safe_part(part))\n    return "/".join(parts) or "file"\n\ndef run_text(argv, timeout=25):\n    try:\n        proc = subprocess.run(\n            argv,\n            text=True,\n            stdout=subprocess.PIPE,\n            stderr=subprocess.PIPE,\n            timeout=timeout,\n            check=False,\n        )\n    except (OSError, subprocess.TimeoutExpired) as exc:\n        return 127, "", clean(exc)\n    return proc.returncode, proc.stdout or "", proc.stderr or ""\n\ndef file_digest(path):\n    h = hashlib.sha256()\n    with path.open("rb") as handle:\n        for chunk in iter(lambda: handle.read(1024 * 1024), b""):\n            h.update(chunk)\n    return h.hexdigest()\n\ndef file_metadata(path):\n    file_type = ""\n    mime_type = ""\n    rc, out, _err = run_text(["file", "-b", str(path)], timeout=8)\n    if rc == 0 and out.strip():\n        file_type = clean(out.strip())\n    rc, out, _err = run_text(["file", "-b", "--mime-type", str(path)], timeout=8)\n    if rc == 0 and out.strip():\n        mime_type = clean(out.strip())\n    return file_type, mime_type\n\ndef mmls_offsets(src):\n    offsets = [(0, "offset_0")]\n    rc, out, err = run_text(["mmls", str(src)], timeout=20)\n    if rc != 0:\n        if err:\n            print(f"{ERROR}\\tmmls\\t0\\t{clean(err)}")\n        return offsets\n    for line in out.splitlines():\n        match = re.match(r"^\\s*\\d+:\\s+\\S+\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(.+?)\\s*$", line)\n        if not match:\n            continue\n        start = int(match.group(1))\n        desc = match.group(4).strip()\n        lowered = desc.lower()\n        if start <= 0 or "unallocated" in lowered or "table" in lowered or "metadata" in lowered:\n            continue\n        if all(start != old for old, _ in offsets):\n            offsets.append((start, desc))\n    return offsets[:12]\n\nFLS_RE = re.compile(r"^\\s*([A-Za-z?]/[A-Za-z?])\\s+\\*?\\s*([^:\\s]+)(?:\\([^)]*\\))?:\\s*(.+)$")\n\ndef list_entries(src, offset):\n    rc, out, err = run_text(["fls", "-o", str(offset), "-r", "-p", str(src)], timeout=35)\n    if rc != 0:\n        if err:\n            print(f"{ERROR}\\tfls\\t{offset}\\t{clean(err)}")\n        return []\n    entries = []\n    for line in out.splitlines():\n        match = FLS_RE.match(line)\n        if not match:\n            continue\n        entry_type, inode, name = match.groups()\n        name = name.strip()\n        if not name or name in {".", ".."}:\n            continue\n        rel = safe_relpath(name)\n        entries.append({\n            "type": entry_type,\n            "inode": inode,\n            "name": rel,\n            "raw_name": clean(name),\n        })\n        if len(entries) <= 200:\n            print(f"{ENTRY}\\t{offset}\\t{clean(entry_type)}\\t{clean(inode)}\\t{clean(name)}")\n    return entries\n\ndef extract_inode(src, out_root, offset, entry, remaining_bytes):\n    dest = out_root / f"offset_{offset}" / entry["name"]\n    dest.parent.mkdir(parents=True, exist_ok=True)\n    try:\n        with dest.open("wb") as handle:\n            proc = subprocess.run(\n                ["icat", "-o", str(offset), str(src), entry["inode"]],\n                stdout=handle,\n                stderr=subprocess.PIPE,\n                timeout=35,\n                check=False,\n            )\n    except (OSError, subprocess.TimeoutExpired) as exc:\n        print(f"{ERROR}\\ticat\\t{offset}\\t{clean(entry[\'name\'])}: {clean(exc)}")\n        dest.unlink(missing_ok=True)\n        return 0, None\n    if proc.returncode != 0:\n        print(f"{ERROR}\\ticat\\t{offset}\\t{clean(entry[\'name\'])}: {clean(proc.stderr.decode(\'utf-8\', \'replace\') if isinstance(proc.stderr, bytes) else proc.stderr)}")\n        dest.unlink(missing_ok=True)\n        return 0, None\n    size = dest.stat().st_size\n    if size <= 0:\n        dest.unlink(missing_ok=True)\n        return 0, None\n    if size > remaining_bytes:\n        dest.unlink(missing_ok=True)\n        print(f"{SKIP}\\tbudget\\t{offset}\\t{clean(entry[\'name\'])}\\t{size}")\n        return 0, None\n    return size, dest\n\ndef zip_extension(names):\n    lowered = {name.lower() for name in names}\n    if "[content_types].xml" in lowered and any(name.startswith("ppt/") for name in lowered):\n        return ".pptx"\n    if "[content_types].xml" in lowered and any(name.startswith("word/") for name in lowered):\n        return ".docx"\n    if "[content_types].xml" in lowered and any(name.startswith("xl/") for name in lowered):\n        return ".xlsx"\n    if "androidmanifest.xml" in lowered:\n        return ".apk"\n    if any(name.endswith(".class") for name in lowered):\n        return ".jar"\n    return ".zip"\n\ndef carve_embedded_zips(src, out_root, remaining_bytes, max_files):\n    if remaining_bytes <= 0 or max_files <= 0:\n        return 0, 0\n    written = 0\n    count = 0\n    try:\n        with src.open("rb") as handle:\n            mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)\n            try:\n                pos = 0\n                covered_until = -1\n                while count < max_files:\n                    start = mm.find(b"PK\\x03\\x04", pos)\n                    if start < 0:\n                        break\n                    if start < covered_until:\n                        pos = start + 4\n                        continue\n                    eocd = mm.find(b"PK\\x05\\x06", start)\n                    if eocd < 0 or eocd + 22 > len(mm):\n                        pos = start + 4\n                        continue\n                    comment_len = int.from_bytes(mm[eocd + 20:eocd + 22], "little")\n                    end = eocd + 22 + comment_len\n                    if end > len(mm) or end <= start:\n                        pos = start + 4\n                        continue\n                    size = end - start\n                    if size > remaining_bytes - written:\n                        print(f"{SKIP}\\tbudget\\t{start}\\tembedded_zip\\t{size}")\n                        break\n                    rel = Path("embedded") / f"zip_{start:x}.zip"\n                    dest = out_root / rel\n                    dest.parent.mkdir(parents=True, exist_ok=True)\n                    dest.write_bytes(mm[start:end])\n                    try:\n                        with zipfile.ZipFile(dest) as zf:\n                            names = zf.namelist()[:400]\n                            zf.testzip()\n                    except zipfile.BadZipFile:\n                        dest.unlink(missing_ok=True)\n                        pos = start + 4\n                        continue\n                    ext = zip_extension(names)\n                    if ext != ".zip":\n                        typed = dest.with_suffix(ext)\n                        dest.replace(typed)\n                        dest = typed\n                    file_size = dest.stat().st_size\n                    digest = file_digest(dest)\n                    file_type, mime_type = file_metadata(dest)\n                    print(f"{FILE}\\t{dest}\\t{file_size}\\tembedded_zip\\t{start}\\tembedded_zip@{start}\\t{start}\\t{digest}\\t{file_type}\\t{mime_type}")\n                    written += file_size\n                    count += 1\n                    covered_until = end\n                    pos = end\n            finally:\n                mm.close()\n    except (OSError, ValueError) as exc:\n        print(f"{ERROR}\\tembedded_zip\\t0\\t{clean(exc)}")\n    return count, written\n\ndef priority(entry):\n    name = entry["name"].lower()\n    ext_order = (\n        ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".7z", ".rar",\n        ".txt", ".xml", ".json", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp",\n        ".pdf", ".sqlite", ".db", ".pcap",\n    )\n    for index, ext in enumerate(ext_order):\n        if name.endswith(ext):\n            return index\n    if name.startswith("."):\n        return 100\n    return 50\n\ndef main():\n    src = Path(sys.argv[1])\n    out_root = Path(sys.argv[2])\n    max_files = int(sys.argv[3])\n    max_bytes = int(sys.argv[4]) * 1024 * 1024\n    explicit_offsets = [int(item) for item in sys.argv[5].split(",") if item.strip().isdigit()]\n    out_root.mkdir(parents=True, exist_ok=True)\n\n    offsets = []\n    for offset in explicit_offsets:\n        offsets.append((offset, "explicit"))\n    for offset, desc in mmls_offsets(src):\n        if all(offset != old for old, _ in offsets):\n            offsets.append((offset, desc))\n\n    total = 0\n    extracted = 0\n    for offset, desc in offsets[:12]:\n        print(f"{PARTITION}\\t{offset}\\t{clean(desc)}")\n        entries = list_entries(src, offset)\n        regular = [entry for entry in entries if entry["type"].lower().startswith("r/")]\n        for entry in sorted(regular, key=priority):\n            if extracted >= max_files or total >= max_bytes:\n                break\n            size, dest = extract_inode(src, out_root, offset, entry, max_bytes - total)\n            if dest is None:\n                continue\n            total += size\n            extracted += 1\n            try:\n                digest = file_digest(dest)\n            except OSError:\n                digest = ""\n            file_type, mime_type = file_metadata(dest)\n            print(f"{FILE}\\t{dest}\\t{size}\\tfilesystem\\t{offset}\\t{clean(entry[\'inode\'])}\\t{clean(entry[\'raw_name\'])}\\t{digest}\\t{file_type}\\t{mime_type}")\n\n    remaining_files = max(0, max_files - extracted)\n    count, written = carve_embedded_zips(src, out_root, max_bytes - total, remaining_files)\n    extracted += count\n    total += written\n    if extracted == 0:\n        shutil.rmtree(out_root, ignore_errors=True)\n    print(f"{SUMMARY}\\t{extracted}\\t{total}\\t{len(offsets)}")\n\nif __name__ == "__main__":\n    main()\n'


class DiskExtractPlugin:
    name = "disk_extract"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        max_files = _positive_int(request.metadata.get("max_files"), _DEFAULT_MAX_FILES)
        max_extract_mb = _positive_int(
            request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB
        )
        offsets = _offsets_arg(request.metadata)
        output_expr = _durable_output_expr(
            source_path=path, requested_output_dir=output_dir, files_root=files_root
        )
        cmd = f'_kc_src={shlex.quote(path)}; _kc_out={output_expr}; python3 -c {shlex.quote(_DISK_EXTRACT_PY)} "$_kc_src" "$_kc_out" {max_files} {max_extract_mb} {shlex.quote(offsets)}'
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd, files_root, preserve_relative_paths=(".autopentest_artifacts",)
                ),
            ],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    source_path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    records = _parse_records(stdout)
    artifacts = [
        Artifact(
            path=record["path"],
            kind=f"disk_extract_{_artifact_kind(record['path'])}",
            source="disk_extract",
            size=record.get("size"),
            digest=record.get("digest"),
            metadata={
                "source_file": source_path,
                "extractor": record.get("extractor"),
                "offset": record.get("offset"),
                "inode": record.get("inode"),
                "source_name": record.get("source_name"),
                **(
                    {"file_type": record["file_type"]}
                    if record.get("file_type")
                    else {}
                ),
                **(
                    {"mime_type": record["mime_type"]}
                    if record.get("mime_type")
                    else {}
                ),
            },
        )
        for record in records["files"][:120]
    ]
    flags = _flag_candidates_from(stdout, source="disk_extract")
    extracted_count = len(records["files"])
    partition_count = len(records["partitions"])
    summary = f"disk.extract {source_path}: {extracted_count} durable file(s) extracted"
    if partition_count:
        summary += f", {partition_count} partition offset(s) inspected"
    if records["skipped"]:
        summary += f", {len(records['skipped'])} item(s) skipped"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    return ToolOutput(
        status=_status(result),
        summary=summary,
        output_text=_truncate(stdout, 5000),
        raw_log=_truncate(stdout + stderr, 8000),
        output_context={
            "path": source_path,
            "extracted_count": extracted_count,
            "extracted_files": [record["path"] for record in records["files"][:120]],
            "extracted_file_records": records["files"][:120],
            "extracted_files_durable": True,
            "partitions": records["partitions"][:40],
            "listing_sample": records["entries"][:200],
            "skipped": records["skipped"][:40],
            "errors": records["errors"][:40],
        },
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _offsets_arg(metadata: dict[str, object]) -> str:
    raw = metadata.get("offsets")
    values: list[str] = []
    if isinstance(raw, (list, tuple, set)):
        values.extend((str(item).strip() for item in raw if str(item).strip()))
    for key in ("offset", "partition_offset"):
        value = str(metadata.get(key) or "").strip()
        if value:
            values.append(value)
    clean: list[str] = []
    for value in values:
        try:
            parsed = int(value, 0)
        except ValueError:
            continue
        if parsed >= 0 and str(parsed) not in clean:
            clean.append(str(parsed))
    return ",".join(clean)


def _safe_stem(path: str) -> str:
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or "artifact"
    return re.sub("[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *, source_path: str, requested_output_dir: str, files_root: str
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return f'"$CTF_FILES_ROOT/.autopentest_artifacts/disk_extract_{_safe_stem(source_path)}{suffix}_$$"'


def _parse_records(stdout: str) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {
        "partitions": [],
        "entries": [],
        "files": [],
        "skipped": [],
        "errors": [],
        "summary": [],
    }
    for line in stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        marker = parts[0]
        if marker == _PARTITION_MARKER and len(parts) >= 3:
            records["partitions"].append(
                {"offset": _int_or_none(parts[1]), "description": parts[2]}
            )
        elif marker == _ENTRY_MARKER and len(parts) >= 5:
            records["entries"].append(
                {
                    "offset": _int_or_none(parts[1]),
                    "type": parts[2],
                    "inode": parts[3],
                    "path": parts[4],
                }
            )
        elif marker == _FILE_MARKER and len(parts) >= 7:
            records["files"].append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "extractor": parts[3],
                    "offset": _int_or_none(parts[4]),
                    "inode": parts[5],
                    "source_name": parts[6],
                    "digest": parts[7] if len(parts) >= 8 and parts[7] else None,
                    "file_type": parts[8] if len(parts) >= 9 and parts[8] else None,
                    "mime_type": parts[9] if len(parts) >= 10 and parts[9] else None,
                }
            )
        elif marker == _SKIP_MARKER and len(parts) >= 5:
            records["skipped"].append(
                {
                    "reason": parts[1],
                    "offset": _int_or_none(parts[2]),
                    "path": parts[3],
                    "size": _int_or_none(parts[4]),
                }
            )
        elif marker == _ERROR_MARKER and len(parts) >= 4:
            records["errors"].append(
                {
                    "stage": parts[1],
                    "offset": _int_or_none(parts[2]),
                    "detail": parts[3],
                }
            )
        elif marker == _SUMMARY_MARKER and len(parts) >= 4:
            records["summary"].append(
                {
                    "extracted_count": _int_or_none(parts[1]),
                    "extracted_bytes": _int_or_none(parts[2]),
                    "partition_count": _int_or_none(parts[3]),
                }
            )
    return records


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _artifact_kind(path: str) -> str:
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in {"ppt", "pptx", "doc", "docx", "xls", "xlsx", "pdf"}:
        return "document"
    if ext in {"zip", "7z", "rar", "gz", "tar"}:
        return "archive"
    if ext in {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff"}:
        return "image"
    if ext in {"mp4", "mov", "avi", "mkv", "mp3", "wav"}:
        return "media"
    if ext in {"txt", "xml", "json", "csv", "md", "log"}:
        return "text"
    if ext in {"sqlite", "db"}:
        return "database"
    return ext or "file"


__all__ = [
    "DiskExtractPlugin",
    "_ENTRY_MARKER",
    "_ERROR_MARKER",
    "_FILE_MARKER",
    "_PARTITION_MARKER",
    "_SKIP_MARKER",
    "_SUMMARY_MARKER",
    "build_output",
]
