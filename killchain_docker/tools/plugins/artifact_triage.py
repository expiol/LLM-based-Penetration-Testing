"""artifact.triage — deterministic first-pass artifact inspection."""

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
    _run,
    _status,
    _truncate,
)
from killchain_docker.tools.plugins.file_cmd import _KIND_MAP
from killchain_docker.tools.plugins.workspace import protected_shell_command


_FILE_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_FILE__"
_FILE_CMD_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_FILE_CMD__"
_EXIF_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_EXIF__"
_STRINGS_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_STRINGS__"
_BINWALK_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_BINWALK__"
_PNG_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_PNG__"
_END_MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_END__"
_PATH_LINE_RE = re.compile(r"^" + re.escape(_FILE_MARKER) + r"\t([^\t]+)\t([0-9]*)$")
_DEFAULT_MAX_STRINGS = 200
_PNG_PROBE_PY = r'''
import binascii
import os
import re
import sys
from pathlib import Path

MARKER = "__KILLCHAIN_ARTIFACT_TRIAGE_PNG__"
STANDARD = {
    "IHDR", "PLTE", "IDAT", "IEND", "tEXt", "zTXt", "iTXt", "bKGD",
    "cHRM", "dSIG", "eXIf", "gAMA", "hIST", "iCCP", "pHYs", "sBIT",
    "sPLT", "sRGB", "sTER", "tIME", "tRNS",
}
TEXTUAL = {"tEXt", "zTXt", "iTXt"}
MAX_EXTRACT = 4 * 1024 * 1024

def clean(value):
    return str(value).replace("\t", " ").replace("\n", " ")[:240]

def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:48] or "artifact"

def preview(blob):
    head = blob[:160]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in head)
    return clean(text)

def hex_preview(blob):
    return blob[:32].hex()

def maybe_write(out_root, name, payload):
    if not payload:
        return ""
    out_root.mkdir(parents=True, exist_ok=True)
    out = out_root / name
    out.write_bytes(payload[:MAX_EXTRACT])
    return str(out)

def main():
    path = Path(sys.argv[1])
    print(MARKER)
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"error\t{clean(exc)}")
        return
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return
    root = Path(os.environ.get("CTF_FILES_ROOT") or "/home/ctfplayer/ctf_files")
    out_root = root / ".autopentest_artifacts" / "png_triage" / safe_name(path.name)
    pos = 8
    index = 0
    saw_iend = False
    while pos + 8 <= len(data) and index < 256:
        length = int.from_bytes(data[pos:pos + 4], "big")
        raw_type = data[pos + 4:pos + 8]
        chunk_type = raw_type.decode("latin1", "replace")
        payload_start = pos + 8
        payload_end = payload_start + length
        crc_end = payload_end + 4
        if payload_end > len(data) or crc_end > len(data):
            print(f"chunk_truncated\t{index}\t{clean(chunk_type)}\t{length}\t{len(data) - pos}")
            break
        payload = data[payload_start:payload_end]
        stored_crc = int.from_bytes(data[payload_end:crc_end], "big")
        crc = binascii.crc32(raw_type)
        crc = binascii.crc32(payload, crc) & 0xFFFFFFFF
        crc_ok = int(crc == stored_crc)
        standard = chunk_type in STANDARD
        artifact = ""
        if (not standard or chunk_type in TEXTUAL) and length <= MAX_EXTRACT:
            artifact = maybe_write(
                out_root,
                f"{index:03d}_{safe_name(chunk_type)}.bin",
                payload,
            )
        print(
            "chunk\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}".format(
                index,
                clean(chunk_type),
                length,
                crc_ok,
                int(standard),
                artifact,
                preview(payload),
                hex_preview(payload),
            )
        )
        pos = crc_end
        index += 1
        if chunk_type == "IEND":
            saw_iend = True
            break
    if saw_iend and pos < len(data):
        trailing = data[pos:]
        artifact = maybe_write(out_root, "trailing_after_iend.bin", trailing)
        print(
            "trailing\t{}\t{}\t{}\t{}".format(
                len(trailing),
                artifact,
                preview(trailing),
                hex_preview(trailing),
            )
        )

if __name__ == "__main__":
    main()
'''


class ArtifactTriagePlugin:
    name = "artifact_triage"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        paths = _paths_from_metadata(request.metadata)
        max_strings = _positive_int(
            request.metadata.get("max_strings"),
            _DEFAULT_MAX_STRINGS,
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
        array_values = " ".join(shlex.quote(path) for path in paths)
        path_setup = f"_kc_paths=({array_values});"
    else:
        path_setup = (
            "mapfile -t _kc_paths < <("
            'find "$CTF_FILES_ROOT" -maxdepth 1 -type f -printf "%p\\n" '
            "2>/dev/null | sort | head -40"
            ");"
        )
    png_probe = f"python3 -c {shlex.quote(_PNG_PROBE_PY)} \"$_kc_path\" 2>/dev/null || true;"
    return " ".join(
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
            '  if command -v exiftool >/dev/null 2>&1; then',
            f'    printf "%s\\n" "{_EXIF_MARKER}";',
            '    exiftool "$_kc_path" 2>/dev/null | sed -n "1,100p" || true;',
            "  fi;",
            f'  printf "%s\\n" "{_STRINGS_MARKER}";',
            f'  strings -n 6 "$_kc_path" 2>/dev/null | head -{max_strings} || true;',
            '  if command -v binwalk >/dev/null 2>&1; then',
            f'    printf "%s\\n" "{_BINWALK_MARKER}";',
            '    timeout 25s binwalk "$_kc_path" 2>/dev/null | sed -n "1,100p" || true;',
            "  fi;",
            png_probe,
            f'  printf "%s\\n" "{_END_MARKER}";',
            "done;",
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

    flags = _flag_candidates_from(
        _candidate_text_from_records(records),
        source="artifact_triage",
    )
    summary = f"artifact.triage: {len(records)} file(s) inspected"
    interesting_count = sum(
        len(record.get("interesting_strings") or []) for record in records
    )
    signature_count = sum(int(record.get("signature_count") or 0) for record in records)
    png_artifact_count = sum(
        len(record.get("png_artifacts") or []) for record in records
    )
    if interesting_count:
        summary += f", {interesting_count} interesting string(s)"
    if signature_count:
        summary += f", {signature_count} binwalk signature(s)"
    if png_artifact_count:
        summary += f", {png_artifact_count} png payload artifact(s)"
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

    strings_lines = [line.strip() for line in sections.get("strings") or [] if line.strip()]
    interesting = _interesting_strings(strings_lines)
    if interesting:
        record["interesting_strings"] = interesting[:25]
    if strings_lines:
        record["string_count_sample"] = len(strings_lines)

    binwalk_lines = [
        line for line in sections.get("binwalk") or []
        if re.match(r"^\d+\s+0x[0-9A-Fa-f]+\s+.+", line.strip())
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
            truncated.append({
                "index": _int_or_none(parts[1]),
                "type": parts[2],
                "declared_length": _int_or_none(parts[3]),
                "remaining_bytes": _int_or_none(parts[4]),
            })
        elif parts[0] == "error" and len(parts) >= 2:
            errors.append(parts[1])
    if not chunks and trailing is None and not truncated and not errors:
        return {}
    out: dict[str, Any] = {
        "chunk_count": len(chunks),
        "chunks": chunks[:40],
    }
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
        lines.extend(str(item) for item in record.get("interesting_strings") or [])
        png = record.get("png")
        if not isinstance(png, dict):
            continue
        for chunk in png.get("text_chunks") or []:
            if isinstance(chunk, dict):
                preview = str(chunk.get("ascii_preview") or "")
                if preview:
                    lines.append(preview)
    return "\n".join(lines)


def _png_artifacts(png: dict[str, Any]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for chunk in png.get("nonstandard_chunks") or []:
        path = str(chunk.get("artifact_path") or "")
        if path:
            chunk_type = str(chunk.get("type") or "chunk")
            artifacts.append({
                "path": path,
                "kind": f"png_chunk_{_safe_kind(chunk_type)}",
                "type": chunk_type,
                "index": chunk.get("index"),
                "size": chunk.get("length"),
            })
    trailing = png.get("trailing_data")
    if isinstance(trailing, dict):
        path = str(trailing.get("artifact_path") or "")
        if path:
            artifacts.append({
                "path": path,
                "kind": "png_trailing_data",
                "type": "trailing_after_iend",
                "index": None,
                "size": trailing.get("size"),
            })
    return artifacts


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _safe_kind(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_").lower() or "payload"


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
        if any(keyword in lower for keyword in keywords):
            if line not in out:
                out.append(line[:220])
    return out
