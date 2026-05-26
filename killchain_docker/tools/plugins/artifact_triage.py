"""artifact.triage — deterministic first-pass artifact inspection."""

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
    _run,
    _status,
)
from killchain_docker.tools.plugins.file_cmd import _KIND_MAP
from killchain_docker.tools.plugins.workspace import protected_shell_command

_FILE_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_FILE__"
_FILE_CMD_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_FILE_CMD__"
_EXIF_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_EXIF__"
_STRINGS_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_STRINGS__"
_BINWALK_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_BINWALK__"
_PNG_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_PNG__"
_ARCHIVE_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_ARCHIVE__"
_END_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_END__"
_PATH_LINE_RE = re.compile("^" + re.escape(_FILE_MARKER) + "\\t([^\\t]+)\\t([0-9]*)$")
_DEFAULT_MAX_STRINGS = 200
_ARCHIVE_PROBE_PY = '\nimport hashlib\nimport os\nimport posixpath\nimport re\nimport sys\nimport tarfile\nimport zipfile\nfrom pathlib import Path\n\nMARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_ARCHIVE__"\nMAX_MEMBERS = 1000\nMAX_LISTED = 200\nMAX_EXTRACTED = 40\nMAX_MEMBER_BYTES = 256 * 1024\nMAX_TOTAL_BYTES = 4 * 1024 * 1024\nSIGNAL_TERMS = (\n    "auth", "credential", "decrypt", "encrypt", "flag", "key", "password",\n    "secret", "session", "token",\n)\n\ndef clean(value, limit=240):\n    return str(value).replace("\\t", " ").replace("\\n", " ")[:limit]\n\ndef safe_name(value):\n    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")[:80] or "artifact"\n\ndef safe_member_name(name):\n    raw = str(name or "").replace("\\\\", "/")\n    raw = raw.split(":", 1)[-1] if re.match(r"^[A-Za-z]:", raw) else raw\n    norm = posixpath.normpath(raw).lstrip("/")\n    if norm in {"", "."}:\n        return ""\n    if norm.startswith("../") or "/../" in f"/{norm}/":\n        return ""\n    return norm\n\ndef textlike(data):\n    if not data:\n        return False\n    sample = data[:4096]\n    if b"\\x00" in sample:\n        return False\n    printable = sum(1 for byte in sample if byte in b"\\n\\r\\t" or 32 <= byte < 127)\n    return printable / max(1, len(sample)) >= 0.85\n\ndef preview(data):\n    sample = data[:220]\n    return clean("".join(chr(byte) if byte in b"\\n\\r\\t" or 32 <= byte < 127 else "." for byte in sample))\n\ndef member_score(name, size, data):\n    score = 1\n    if size <= MAX_MEMBER_BYTES:\n        score += 10\n    if textlike(data):\n        score += 50\n    lowered = data[:8192].decode("latin1", "ignore").lower()\n    score += min(40, 8 * sum(1 for term in SIGNAL_TERMS if term in lowered))\n    depth = safe_member_name(name).count("/")\n    score += max(0, 12 - depth)\n    return score\n\ndef archive_root(path):\n    root = Path(os.environ.get("CTF_FILES_ROOT") or "/home/ctfplayer/ctf_files")\n    digest = hashlib.sha256(str(path).encode("utf-8", "ignore")).hexdigest()[:12]\n    return root / ".autopentest_artifacts" / "archive_triage" / f"{safe_name(Path(path).name)}_{digest}"\n\ndef read_tar_member(archive, member):\n    handle = archive.extractfile(member)\n    if handle is None:\n        return b""\n    try:\n        return handle.read(MAX_MEMBER_BYTES + 1)\n    finally:\n        handle.close()\n\ndef tar_entries(path):\n    with tarfile.open(path, "r:*") as archive:\n        for member in archive:\n            if not member.isfile():\n                continue\n            safe = safe_member_name(member.name)\n            if not safe:\n                continue\n            data = b""\n            if int(member.size or 0) <= MAX_MEMBER_BYTES:\n                try:\n                    data = read_tar_member(archive, member)\n                except Exception:\n                    data = b""\n            yield {\n                "name": safe,\n                "size": int(member.size or 0),\n                "data": data,\n            }\n\ndef zip_entries(path):\n    with zipfile.ZipFile(path) as archive:\n        for info in archive.infolist():\n            if info.is_dir():\n                continue\n            safe = safe_member_name(info.filename)\n            if not safe:\n                continue\n            data = b""\n            if int(info.file_size or 0) <= MAX_MEMBER_BYTES:\n                try:\n                    with archive.open(info) as handle:\n                        data = handle.read(MAX_MEMBER_BYTES + 1)\n                except Exception:\n                    data = b""\n            yield {\n                "name": safe,\n                "size": int(info.file_size or 0),\n                "data": data,\n            }\n\ndef main():\n    path = Path(sys.argv[1])\n    print(MARKER)\n    try:\n        if zipfile.is_zipfile(path):\n            entries = list(zip_entries(path))\n            archive_type = "zip"\n        elif tarfile.is_tarfile(path):\n            entries = list(tar_entries(path))\n            archive_type = "tar"\n        else:\n            return\n    except Exception as exc:\n        print(f"error\\t{clean(type(exc).__name__)}\\t{clean(exc)}")\n        return\n    entries = entries[:MAX_MEMBERS]\n    print(f"archive\\t{archive_type}\\t{len(entries)}")\n    for index, entry in enumerate(entries[:MAX_LISTED]):\n        print(f"member\\t{index}\\t{entry[\'size\']}\\t{clean(entry[\'name\'], 500)}")\n    candidates = []\n    for entry in entries:\n        if entry["size"] > MAX_MEMBER_BYTES:\n            continue\n        data = entry.get("data", b"")\n        if len(data) > MAX_MEMBER_BYTES:\n            continue\n        candidates.append((member_score(entry["name"], entry["size"], data), entry, data))\n    candidates.sort(key=lambda item: (-item[0], item[1]["size"], item[1]["name"]))\n    out_root = archive_root(path)\n    total = 0\n    extracted = 0\n    for score, entry, data in candidates:\n        if extracted >= MAX_EXTRACTED:\n            break\n        if total + len(data) > MAX_TOTAL_BYTES:\n            break\n        dest = out_root / entry["name"]\n        dest.parent.mkdir(parents=True, exist_ok=True)\n        dest.write_bytes(data)\n        digest = hashlib.sha256(data).hexdigest()\n        total += len(data)\n        extracted += 1\n        kind = "text" if textlike(data) else "data"\n        print(\n            "artifact\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}".format(\n                dest,\n                len(data),\n                clean(entry["name"], 500),\n                digest,\n                score,\n                kind,\n                preview(data),\n            )\n        )\n\nif __name__ == "__main__":\n    main()\n'
_PNG_PROBE_PY = '\nimport binascii\nimport os\nimport re\nimport sys\nfrom pathlib import Path\n\nMARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_PNG__"\nSTANDARD = {\n    "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "bKGD",\n    "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "pHYs", "sBIT",\n    "sPLT", "sRGB", "sTER", "tIME", "tRNS",\n}\nTEXTUAL = {"tEXt", "zTXt", "iTXt"}\nMAX_EXTRACT = 4 * 1024 * 1024\n\ndef clean(value):\n    return str(value).replace("\\t", " ").replace("\\n", " ")[:240]\n\ndef safe_name(value):\n    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:48] or "artifact"\n\ndef preview(blob):\n    head = blob[:160]\n    text = "".join(chr(b) if 32 <= b < 127 else "." for b in head)\n    return clean(text)\n\ndef hex_preview(blob):\n    return blob[:32].hex()\n\ndef maybe_write(out_root, name, payload):\n    if not payload:\n        return ""\n    out_root.mkdir(parents=True, exist_ok=True)\n    out = out_root / name\n    out.write_bytes(payload[:MAX_EXTRACT])\n    return str(out)\n\ndef main():\n    path = Path(sys.argv[1])\n    print(MARKER)\n    try:\n        data = path.read_bytes()\n    except OSError as exc:\n        print(f"error\\t{clean(exc)}")\n        return\n    if not data.startswith(b"\\x89PNG\\r\\n\\x1a\\n"):\n        return\n    root = Path(os.environ.get("CTF_FILES_ROOT") or "/home/ctfplayer/ctf_files")\n    out_root = root / ".autopentest_artifacts" / "png_triage" / safe_name(path.name)\n    pos = 8\n    index = 0\n    saw_iend = False\n    while pos + 8 <= len(data) and index < 256:\n        length = int.from_bytes(data[pos:pos + 4], "big")\n        raw_type = data[pos + 4:pos + 8]\n        chunk_type = raw_type.decode("latin1", "replace")\n        payload_start = pos + 8\n        payload_end = payload_start + length\n        crc_end = payload_end + 4\n        if payload_end > len(data) or crc_end > len(data):\n            print(f"chunk_truncated\\t{index}\\t{clean(chunk_type)}\\t{length}\\t{len(data) - pos}")\n            break\n        payload = data[payload_start:payload_end]\n        stored_crc = int.from_bytes(data[payload_end:crc_end], "big")\n        crc = binascii.crc32(raw_type)\n        crc = binascii.crc32(payload, crc) & 0xFFFFFFFF\n        crc_ok = int(crc == stored_crc)\n        standard = chunk_type in STANDARD\n        artifact = ""\n        if (not standard or chunk_type in TEXTUAL) and length <= MAX_EXTRACT:\n            artifact = maybe_write(\n                out_root,\n                f"{index:03d}_{safe_name(chunk_type)}.bin",\n                payload,\n            )\n        print(\n            "chunk\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}\\t{}".format(\n                index,\n                clean(chunk_type),\n                length,\n                crc_ok,\n                int(standard),\n                artifact,\n                preview(payload),\n                hex_preview(payload),\n            )\n        )\n        pos = crc_end\n        index += 1\n        if chunk_type == "IEND":\n            saw_iend = True\n            break\n    if saw_iend and pos < len(data):\n        trailing = data[pos:]\n        artifact = maybe_write(out_root, "trailing_after_iend.bin", trailing)\n        print(\n            "trailing\\t{}\\t{}\\t{}\\t{}".format(\n                len(trailing),\n                artifact,\n                preview(trailing),\n                hex_preview(trailing),\n            )\n        )\n\nif __name__ == "__main__":\n    main()\n'


class ArtifactTriagePlugin:
    name = "artifact_triage"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        paths = _paths_from_metadata(request.metadata)
        max_strings = _positive_int(
            request.metadata.get("max_strings"), _DEFAULT_MAX_STRINGS
        )
        command = _triage_command(paths, max_strings=max_strings)
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    command,
                    files_root,
                    preserve_relative_paths=(".autopentest_artifacts",),
                ),
            ],
            request.timeout_s,
        )


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _paths_from_metadata(metadata: dict[str, object]) -> list[str]:
    raw = metadata.get("paths")
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    path = str(metadata.get("path") or "").strip()
    return [path] if path else []


def _triage_command(paths: list[str], *, max_strings: int) -> str:
    if paths:
        array_values = " ".join((shlex.quote(path) for path in paths))
        path_setup = f"_kc_paths=({array_values});"
    else:
        path_setup = 'mapfile -t _kc_paths < <(find "$CTF_FILES_ROOT" -maxdepth 1 -type f -printf "%p\\n" 2>/dev/null | sort | head -40);'
    png_probe = (
        f'python3 -c {shlex.quote(_PNG_PROBE_PY)} "$_kc_path" 2>/dev/null || true;'
    )
    archive_probe = (
        f'python3 -c {shlex.quote(_ARCHIVE_PROBE_PY)} "$_kc_path" 2>/dev/null || true;'
    )
    return " ".join(
        (
            part.strip()
            for part in (
                "set -u;",
                path_setup,
                'for _kc_path in "${_kc_paths[@]}"; do',
                '  [ -e "$_kc_path" ] || continue;',
                '  _kc_size=$(stat -c%s "$_kc_path" 2>/dev/null || echo "");',
                f'  printf "%s\\t%s\\t%s\\n" "{_FILE_MARKER}" "$_kc_path" "$_kc_size";',
                f'  printf "%s\\n" "{_FILE_CMD_MARKER}";',
                '  file -b "$_kc_path" 2>/dev/null || true;',
                '  file -b --mime-type "$_kc_path" 2>/dev/null || true;',
                "  if command -v exiftool >/dev/null 2>&1; then",
                f'    printf "%s\\n" "{_EXIF_MARKER}";',
                '    exiftool "$_kc_path" 2>/dev/null | sed -n "1,100p" || true;',
                "  fi;",
                f'  printf "%s\\n" "{_STRINGS_MARKER}";',
                f'  strings -n 6 "$_kc_path" 2>/dev/null | head -{max_strings} || true;',
                "  if command -v binwalk >/dev/null 2>&1; then",
                f'    printf "%s\\n" "{_BINWALK_MARKER}";',
                '    timeout 25s binwalk "$_kc_path" 2>/dev/null | sed -n "1,100p" || true;',
                "  fi;",
                png_probe,
                archive_probe,
                f'  printf "%s\\n" "{_END_MARKER}";',
                "done;",
            )
        )
    )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    records = _parse_records(stdout)
    artifacts: list[Artifact] = []
    for record in records:
        path = str(record.get("path") or "")
        if not path:
            continue
        metadata: dict[str, Any] = {}
        if record.get("file_type"):
            metadata["file_type"] = record["file_type"]
        if record.get("mime_type"):
            metadata["mime_type"] = record["mime_type"]
        if record.get("interesting_strings"):
            metadata["interesting_strings"] = record["interesting_strings"]
        if record.get("signature_count"):
            metadata["signature_count"] = record["signature_count"]
        if record.get("png"):
            metadata["png"] = record["png"]
        if record.get("archive"):
            metadata["archive"] = record["archive"]
        artifacts.append(
            Artifact(
                path=path,
                kind=str(record.get("kind") or "unknown"),
                source="artifact_triage",
                size=record.get("size"),
                metadata=metadata,
            )
        )
        for artifact_record in record.get("png_artifacts") or []:
            artifact_path = str(artifact_record.get("path") or "")
            if not artifact_path:
                continue
            artifacts.append(
                Artifact(
                    path=artifact_path,
                    kind=str(artifact_record.get("kind") or "png_payload"),
                    source="artifact_triage_png",
                    size=artifact_record.get("size"),
                    metadata={
                        "source_file": path,
                        "png_type": artifact_record.get("type"),
                        "png_index": artifact_record.get("index"),
                    },
                )
            )
        for artifact_record in record.get("archive_artifacts") or []:
            artifact_path = str(artifact_record.get("path") or "")
            if not artifact_path:
                continue
            kind = str(artifact_record.get("kind") or "data")
            artifacts.append(
                Artifact(
                    path=artifact_path,
                    kind=f"archive_member_{kind}",
                    source="artifact_triage_archive",
                    size=artifact_record.get("size"),
                    digest=str(artifact_record.get("digest") or "") or None,
                    metadata={
                        "source_file": path,
                        "relative_path": artifact_record.get("member"),
                        "file_type": "ASCII text" if kind == "text" else "data",
                        "mime_type": "text/plain"
                        if kind == "text"
                        else "application/octet-stream",
                        "archive_member_score": artifact_record.get("score"),
                        "content_signals": ["archive_member", kind],
                    },
                )
            )
    flags = _flag_candidates_from(
        _candidate_text_from_records(records), source="artifact_triage"
    )
    summary = f"artifact.triage: {len(records)} file(s) inspected"
    interesting_count = sum(
        (len(record.get("interesting_strings") or []) for record in records)
    )
    signature_count = sum(
        (int(record.get("signature_count") or 0) for record in records)
    )
    png_artifact_count = sum(
        (len(record.get("png_artifacts") or []) for record in records)
    )
    archive_artifact_count = sum(
        (len(record.get("archive_artifacts") or []) for record in records)
    )
    if interesting_count:
        summary += f", {interesting_count} interesting string(s)"
    if signature_count:
        summary += f", {signature_count} binwalk signature(s)"
    if png_artifact_count:
        summary += f", {png_artifact_count} png payload artifact(s)"
    if archive_artifact_count:
        summary += f", {archive_artifact_count} archive member artifact(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 5000),
        raw_log=_truncate(stdout + stderr, 7000),
        output_context={
            "records": records[:40],
            "inspected_count": len(records),
            "paths": [record["path"] for record in records if record.get("path")],
        },
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _parse_records(stdout: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    section = ""
    for line in stdout.splitlines():
        match = _PATH_LINE_RE.match(line)
        if match:
            if current is not None:
                _finalize_record(current)
                records.append(current)
            current = {"path": match.group(1), "raw_sections": {}}
            try:
                current["size"] = int(match.group(2))
            except ValueError:
                pass
            section = ""
            continue
        if current is None:
            continue
        if line == _END_MARKER:
            _finalize_record(current)
            records.append(current)
            current = None
            section = ""
            continue
        if line == _FILE_CMD_MARKER:
            section = "file"
            continue
        if line == _EXIF_MARKER:
            section = "exif"
            continue
        if line == _STRINGS_MARKER:
            section = "strings"
            continue
        if line == _BINWALK_MARKER:
            section = "binwalk"
            continue
        if line == _PNG_MARKER:
            section = "png"
            continue
        if line == _ARCHIVE_MARKER:
            section = "archive"
            continue
        if not section:
            continue
        bucket = current.setdefault("raw_sections", {}).setdefault(section, [])
        bucket.append(line)
    if current is not None:
        _finalize_record(current)
        records.append(current)
    return records


def _finalize_record(record: dict[str, Any]) -> None:
    sections = record.get("raw_sections") or {}
    file_lines = list(sections.get("file") or [])
    file_type = file_lines[0].strip() if file_lines else ""
    mime_type = file_lines[1].strip() if len(file_lines) > 1 else ""
    record["file_type"] = file_type
    if mime_type:
        record["mime_type"] = mime_type
    record["kind"] = _classify_kind(file_type)
    strings_lines = [
        line.strip() for line in sections.get("strings") or [] if line.strip()
    ]
    interesting = _interesting_strings(strings_lines)
    if interesting:
        record["interesting_strings"] = interesting[:25]
    if strings_lines:
        record["string_count_sample"] = len(strings_lines)
    binwalk_lines = [
        line
        for line in sections.get("binwalk") or []
        if re.match("^\\d+\\s+0x[0-9A-Fa-f]+\\s+.+", line.strip())
    ]
    if binwalk_lines:
        record["signature_count"] = len(binwalk_lines)
        record["signatures"] = binwalk_lines[:20]
    png = _parse_png_section(list(sections.get("png") or []))
    if png:
        record["png"] = png
        artifacts = _png_artifacts(png)
        if artifacts:
            record["png_artifacts"] = artifacts
    archive = _parse_archive_section(list(sections.get("archive") or []))
    if archive:
        record["archive"] = archive
        artifacts = _archive_artifacts(archive)
        if artifacts:
            record["archive_artifacts"] = artifacts
    record.pop("raw_sections", None)


def _parse_png_section(lines: list[str]) -> dict[str, Any]:
    chunks: list[dict[str, Any]] = []
    nonstandard: list[dict[str, Any]] = []
    textual: list[dict[str, Any]] = []
    trailing: dict[str, Any] | None = None
    truncated: list[dict[str, Any]] = []
    errors: list[str] = []
    for line in lines:
        parts = line.split("\t")
        if not parts:
            continue
        if parts[0] == "chunk" and len(parts) >= 9:
            chunk = {
                "index": _int_or_none(parts[1]),
                "type": parts[2],
                "length": _int_or_none(parts[3]),
                "crc_ok": parts[4] == "1",
                "standard": parts[5] == "1",
                "artifact_path": parts[6] or None,
                "ascii_preview": parts[7],
                "hex_preview": parts[8],
            }
            chunks.append(chunk)
            if not chunk["standard"]:
                nonstandard.append(chunk)
            if chunk["type"] in {"tEXt", "zTXt", "iTXt"}:
                textual.append(chunk)
        elif parts[0] == "trailing" and len(parts) >= 5:
            trailing = {
                "size": _int_or_none(parts[1]),
                "artifact_path": parts[2] or None,
                "ascii_preview": parts[3],
                "hex_preview": parts[4],
            }
        elif parts[0] == "chunk_truncated" and len(parts) >= 5:
            truncated.append(
                {
                    "index": _int_or_none(parts[1]),
                    "type": parts[2],
                    "declared_length": _int_or_none(parts[3]),
                    "remaining_bytes": _int_or_none(parts[4]),
                }
            )
        elif parts[0] == "error" and len(parts) >= 2:
            errors.append(parts[1])
    if not chunks and trailing is None and (not truncated) and (not errors):
        return {}
    out: dict[str, Any] = {"chunk_count": len(chunks), "chunks": chunks[:40]}
    if nonstandard:
        out["nonstandard_chunks"] = nonstandard[:20]
    if textual:
        out["text_chunks"] = textual[:20]
    if trailing is not None:
        out["trailing_data"] = trailing
    if truncated:
        out["truncated_chunks"] = truncated[:10]
    if errors:
        out["errors"] = errors[:5]
    return out


def _candidate_text_from_records(records: list[dict[str, Any]]) -> str:
    lines: list[str] = []
    for record in records:
        lines.extend((str(item) for item in record.get("interesting_strings") or []))
        png = record.get("png")
        if not isinstance(png, dict):
            continue
        for chunk in png.get("text_chunks") or []:
            if isinstance(chunk, dict):
                preview = str(chunk.get("ascii_preview") or "")
                if preview:
                    lines.append(preview)
        archive = record.get("archive")
        if isinstance(archive, dict):
            for artifact in archive.get("artifacts") or []:
                if isinstance(artifact, dict):
                    preview = str(artifact.get("preview") or "")
                    if preview:
                        lines.append(preview)
    return "\n".join(lines)


def _png_artifacts(png: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for chunk in png.get("nonstandard_chunks") or []:
        path = str(chunk.get("artifact_path") or "")
        if path:
            chunk_type = str(chunk.get("type") or "chunk")
            artifacts.append(
                {
                    "path": path,
                    "kind": f"png_chunk_{_safe_kind(chunk_type)}",
                    "type": chunk_type,
                    "index": chunk.get("index"),
                    "size": chunk.get("length"),
                }
            )
    trailing = png.get("trailing_data")
    if isinstance(trailing, dict):
        path = str(trailing.get("artifact_path") or "")
        if path:
            artifacts.append(
                {
                    "path": path,
                    "kind": "png_trailing_data",
                    "type": "trailing_after_iend",
                    "index": None,
                    "size": trailing.get("size"),
                }
            )
    return artifacts


def _parse_archive_section(lines: list[str]) -> dict[str, Any]:
    archive_type = ""
    member_count: int | None = None
    members: list[dict[str, Any]] = []
    artifacts: list[dict[str, Any]] = []
    errors: list[str] = []
    for line in lines:
        parts = line.split("\t")
        if not parts:
            continue
        if parts[0] == "archive" and len(parts) >= 3:
            archive_type = parts[1]
            member_count = _int_or_none(parts[2])
        elif parts[0] == "member" and len(parts) >= 4:
            members.append(
                {
                    "index": _int_or_none(parts[1]),
                    "size": _int_or_none(parts[2]),
                    "name": parts[3],
                }
            )
        elif parts[0] == "artifact" and len(parts) >= 8:
            artifacts.append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "member": parts[3],
                    "digest": parts[4],
                    "score": _int_or_none(parts[5]),
                    "kind": parts[6],
                    "preview": parts[7],
                }
            )
        elif parts[0] == "error" and len(parts) >= 3:
            errors.append(f"{parts[1]}: {parts[2]}")
    if not archive_type and (not members) and (not artifacts) and (not errors):
        return {}
    out: dict[str, Any] = {}
    if archive_type:
        out["type"] = archive_type
    if member_count is not None:
        out["member_count"] = member_count
    if members:
        out["members"] = members[:200]
    if artifacts:
        out["artifacts"] = artifacts[:40]
    if errors:
        out["errors"] = errors[:5]
    return out


def _archive_artifacts(archive: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        artifact
        for artifact in archive.get("artifacts") or []
        if isinstance(artifact, dict) and artifact.get("path")
    ]


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _safe_kind(value: str) -> str:
    return re.sub("[^A-Za-z0-9_.-]+", "_", value).strip("_").lower() or "payload"


def _classify_kind(file_type: str) -> str:
    lower = file_type.lower()
    for keyword, kind in _KIND_MAP:
        if keyword in lower:
            return kind
    return "unknown"


def _interesting_strings(lines: list[str]) -> list[str]:
    keywords = (
        "flag",
        "ctf",
        "key",
        "secret",
        "password",
        "token",
        "clam",
        "pearl",
        "metadata",
        "comment",
    )
    out: list[str] = []
    for line in lines:
        lower = line.lower()
        if any((keyword in lower for keyword in keywords)):
            if line not in out:
                out.append(line[:220])
    return out
