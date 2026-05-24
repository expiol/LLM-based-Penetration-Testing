"""disk.extract — bounded durable extraction from disk images."""

from __future__ import annotations

import re
import shlex
from typing import Any

from killchain_docker.state import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
    _truncate,
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
_DISK_EXTRACT_PY = r'''
import hashlib
import mmap
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

PARTITION = "__KILLCHAIN_DISK_EXTRACT_PARTITION__"
ENTRY = "__KILLCHAIN_DISK_EXTRACT_ENTRY__"
FILE = "__KILLCHAIN_DISK_EXTRACT_FILE__"
SKIP = "__KILLCHAIN_DISK_EXTRACT_SKIP__"
ERROR = "__KILLCHAIN_DISK_EXTRACT_ERROR__"
SUMMARY = "__KILLCHAIN_DISK_EXTRACT_SUMMARY__"

def clean(value):
    return str(value).replace("\t", " ").replace("\n", " ")[:240]

def safe_part(value):
    out = re.sub(r"[^A-Za-z0-9_.@%+=,-]+", "_", str(value).strip())
    return out.strip("._")[:80] or "file"

def safe_relpath(value):
    text = str(value).replace("\\", "/").strip().strip("/")
    parts = []
    for part in text.split("/"):
        if not part or part in {".", ".."}:
            continue
        parts.append(safe_part(part))
    return "/".join(parts) or "file"

def run_text(argv, timeout=25):
    try:
        proc = subprocess.run(
            argv,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, "", clean(exc)
    return proc.returncode, proc.stdout or "", proc.stderr or ""

def file_digest(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def file_metadata(path):
    file_type = ""
    mime_type = ""
    rc, out, _err = run_text(["file", "-b", str(path)], timeout=8)
    if rc == 0 and out.strip():
        file_type = clean(out.strip())
    rc, out, _err = run_text(["file", "-b", "--mime-type", str(path)], timeout=8)
    if rc == 0 and out.strip():
        mime_type = clean(out.strip())
    return file_type, mime_type

def mmls_offsets(src):
    offsets = [(0, "offset_0")]
    rc, out, err = run_text(["mmls", str(src)], timeout=20)
    if rc != 0:
        if err:
            print(f"{ERROR}\tmmls\t0\t{clean(err)}")
        return offsets
    for line in out.splitlines():
        match = re.match(r"^\s*\d+:\s+\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+(.+?)\s*$", line)
        if not match:
            continue
        start = int(match.group(1))
        desc = match.group(4).strip()
        lowered = desc.lower()
        if start <= 0 or "unallocated" in lowered or "table" in lowered or "metadata" in lowered:
            continue
        if all(start != old for old, _ in offsets):
            offsets.append((start, desc))
    return offsets[:12]

FLS_RE = re.compile(r"^\s*([A-Za-z?]/[A-Za-z?])\s+\*?\s*([^:\s]+)(?:\([^)]*\))?:\s*(.+)$")

def list_entries(src, offset):
    rc, out, err = run_text(["fls", "-o", str(offset), "-r", "-p", str(src)], timeout=35)
    if rc != 0:
        if err:
            print(f"{ERROR}\tfls\t{offset}\t{clean(err)}")
        return []
    entries = []
    for line in out.splitlines():
        match = FLS_RE.match(line)
        if not match:
            continue
        entry_type, inode, name = match.groups()
        name = name.strip()
        if not name or name in {".", ".."}:
            continue
        rel = safe_relpath(name)
        entries.append({
            "type": entry_type,
            "inode": inode,
            "name": rel,
            "raw_name": clean(name),
        })
        if len(entries) <= 200:
            print(f"{ENTRY}\t{offset}\t{clean(entry_type)}\t{clean(inode)}\t{clean(name)}")
    return entries

def extract_inode(src, out_root, offset, entry, remaining_bytes):
    dest = out_root / f"offset_{offset}" / entry["name"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with dest.open("wb") as handle:
            proc = subprocess.run(
                ["icat", "-o", str(offset), str(src), entry["inode"]],
                stdout=handle,
                stderr=subprocess.PIPE,
                timeout=35,
                check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"{ERROR}\ticat\t{offset}\t{clean(entry['name'])}: {clean(exc)}")
        dest.unlink(missing_ok=True)
        return 0, None
    if proc.returncode != 0:
        print(f"{ERROR}\ticat\t{offset}\t{clean(entry['name'])}: {clean(proc.stderr.decode('utf-8', 'replace') if isinstance(proc.stderr, bytes) else proc.stderr)}")
        dest.unlink(missing_ok=True)
        return 0, None
    size = dest.stat().st_size
    if size <= 0:
        dest.unlink(missing_ok=True)
        return 0, None
    if size > remaining_bytes:
        dest.unlink(missing_ok=True)
        print(f"{SKIP}\tbudget\t{offset}\t{clean(entry['name'])}\t{size}")
        return 0, None
    return size, dest

def zip_extension(names):
    lowered = {name.lower() for name in names}
    if "[content_types].xml" in lowered and any(name.startswith("ppt/") for name in lowered):
        return ".pptx"
    if "[content_types].xml" in lowered and any(name.startswith("word/") for name in lowered):
        return ".docx"
    if "[content_types].xml" in lowered and any(name.startswith("xl/") for name in lowered):
        return ".xlsx"
    if "androidmanifest.xml" in lowered:
        return ".apk"
    if any(name.endswith(".class") for name in lowered):
        return ".jar"
    return ".zip"

def carve_embedded_zips(src, out_root, remaining_bytes, max_files):
    if remaining_bytes <= 0 or max_files <= 0:
        return 0, 0
    written = 0
    count = 0
    try:
        with src.open("rb") as handle:
            mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                pos = 0
                covered_until = -1
                while count < max_files:
                    start = mm.find(b"PK\x03\x04", pos)
                    if start < 0:
                        break
                    if start < covered_until:
                        pos = start + 4
                        continue
                    eocd = mm.find(b"PK\x05\x06", start)
                    if eocd < 0 or eocd + 22 > len(mm):
                        pos = start + 4
                        continue
                    comment_len = int.from_bytes(mm[eocd + 20:eocd + 22], "little")
                    end = eocd + 22 + comment_len
                    if end > len(mm) or end <= start:
                        pos = start + 4
                        continue
                    size = end - start
                    if size > remaining_bytes - written:
                        print(f"{SKIP}\tbudget\t{start}\tembedded_zip\t{size}")
                        break
                    rel = Path("embedded") / f"zip_{start:x}.zip"
                    dest = out_root / rel
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_bytes(mm[start:end])
                    try:
                        with zipfile.ZipFile(dest) as zf:
                            names = zf.namelist()[:400]
                            zf.testzip()
                    except zipfile.BadZipFile:
                        dest.unlink(missing_ok=True)
                        pos = start + 4
                        continue
                    ext = zip_extension(names)
                    if ext != ".zip":
                        typed = dest.with_suffix(ext)
                        dest.replace(typed)
                        dest = typed
                    file_size = dest.stat().st_size
                    digest = file_digest(dest)
                    file_type, mime_type = file_metadata(dest)
                    print(f"{FILE}\t{dest}\t{file_size}\tembedded_zip\t{start}\tembedded_zip@{start}\t{start}\t{digest}\t{file_type}\t{mime_type}")
                    written += file_size
                    count += 1
                    covered_until = end
                    pos = end
            finally:
                mm.close()
    except (OSError, ValueError) as exc:
        print(f"{ERROR}\tembedded_zip\t0\t{clean(exc)}")
    return count, written

def priority(entry):
    name = entry["name"].lower()
    ext_order = (
        ".ppt", ".pptx", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".7z", ".rar",
        ".txt", ".xml", ".json", ".csv", ".png", ".jpg", ".jpeg", ".gif", ".bmp",
        ".pdf", ".sqlite", ".db", ".pcap",
    )
    for index, ext in enumerate(ext_order):
        if name.endswith(ext):
            return index
    if name.startswith("."):
        return 100
    return 50

def main():
    src = Path(sys.argv[1])
    out_root = Path(sys.argv[2])
    max_files = int(sys.argv[3])
    max_bytes = int(sys.argv[4]) * 1024 * 1024
    explicit_offsets = [int(item) for item in sys.argv[5].split(",") if item.strip().isdigit()]
    out_root.mkdir(parents=True, exist_ok=True)

    offsets = []
    for offset in explicit_offsets:
        offsets.append((offset, "explicit"))
    for offset, desc in mmls_offsets(src):
        if all(offset != old for old, _ in offsets):
            offsets.append((offset, desc))

    total = 0
    extracted = 0
    for offset, desc in offsets[:12]:
        print(f"{PARTITION}\t{offset}\t{clean(desc)}")
        entries = list_entries(src, offset)
        regular = [entry for entry in entries if entry["type"].lower().startswith("r/")]
        for entry in sorted(regular, key=priority):
            if extracted >= max_files or total >= max_bytes:
                break
            size, dest = extract_inode(src, out_root, offset, entry, max_bytes - total)
            if dest is None:
                continue
            total += size
            extracted += 1
            try:
                digest = file_digest(dest)
            except OSError:
                digest = ""
            file_type, mime_type = file_metadata(dest)
            print(f"{FILE}\t{dest}\t{size}\tfilesystem\t{offset}\t{clean(entry['inode'])}\t{clean(entry['raw_name'])}\t{digest}\t{file_type}\t{mime_type}")

    remaining_files = max(0, max_files - extracted)
    count, written = carve_embedded_zips(src, out_root, max_bytes - total, remaining_files)
    extracted += count
    total += written
    if extracted == 0:
        shutil.rmtree(out_root, ignore_errors=True)
    print(f"{SUMMARY}\t{extracted}\t{total}\t{len(offsets)}")

if __name__ == "__main__":
    main()
'''


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
            request.metadata.get("max_extract_mb"),
            _DEFAULT_MAX_EXTRACT_MB,
        )
        offsets = _offsets_arg(request.metadata)
        output_expr = _durable_output_expr(
            source_path=path,
            requested_output_dir=output_dir,
            files_root=files_root,
        )
        cmd = (
            f"_kc_src={shlex.quote(path)}; "
            f"_kc_out={output_expr}; "
            f"python3 -c {shlex.quote(_DISK_EXTRACT_PY)} "
            f'"$_kc_src" "$_kc_out" {max_files} {max_extract_mb} {shlex.quote(offsets)}'
        )
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd,
                    files_root,
                    preserve_relative_paths=(".autopentest_artifacts",),
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
                **({"file_type": record["file_type"]} if record.get("file_type") else {}),
                **({"mime_type": record["mime_type"]} if record.get("mime_type") else {}),
            },
        )
        for record in records["files"][:120]
    ]
    flags = _flag_candidates_from(stdout, source="disk_extract")
    extracted_count = len(records["files"])
    partition_count = len(records["partitions"])
    summary = (
        f"disk.extract {source_path}: {extracted_count} durable file(s) extracted"
    )
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
        values.extend(str(item).strip() for item in raw if str(item).strip())
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
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *,
    source_path: str,
    requested_output_dir: str,
    files_root: str,
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)

    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return (
        '"$CTF_FILES_ROOT/.autopentest_artifacts/disk_extract_'
        f'{_safe_stem(source_path)}{suffix}_$$"'
    )


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
            records["partitions"].append({
                "offset": _int_or_none(parts[1]),
                "description": parts[2],
            })
        elif marker == _ENTRY_MARKER and len(parts) >= 5:
            records["entries"].append({
                "offset": _int_or_none(parts[1]),
                "type": parts[2],
                "inode": parts[3],
                "path": parts[4],
            })
        elif marker == _FILE_MARKER and len(parts) >= 7:
            records["files"].append({
                "path": parts[1],
                "size": _int_or_none(parts[2]),
                "extractor": parts[3],
                "offset": _int_or_none(parts[4]),
                "inode": parts[5],
                "source_name": parts[6],
                "digest": parts[7] if len(parts) >= 8 and parts[7] else None,
                "file_type": parts[8] if len(parts) >= 9 and parts[8] else None,
                "mime_type": parts[9] if len(parts) >= 10 and parts[9] else None,
            })
        elif marker == _SKIP_MARKER and len(parts) >= 5:
            records["skipped"].append({
                "reason": parts[1],
                "offset": _int_or_none(parts[2]),
                "path": parts[3],
                "size": _int_or_none(parts[4]),
            })
        elif marker == _ERROR_MARKER and len(parts) >= 4:
            records["errors"].append({
                "stage": parts[1],
                "offset": _int_or_none(parts[2]),
                "detail": parts[3],
            })
        elif marker == _SUMMARY_MARKER and len(parts) >= 4:
            records["summary"].append({
                "extracted_count": _int_or_none(parts[1]),
                "extracted_bytes": _int_or_none(parts[2]),
                "partition_count": _int_or_none(parts[3]),
            })
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
