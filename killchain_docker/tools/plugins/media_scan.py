"""media.scan - deterministic batch inspection for embedded media files."""

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
from killchain_docker.tools.plugins.workspace import protected_shell_command


_MEDIA_MARKER = "__KILLCHAIN_MEDIA_SCAN_FILE__"
_ARTIFACT_MARKER = "__KILLCHAIN_MEDIA_SCAN_ARTIFACT__"
_ERROR_MARKER = "__KILLCHAIN_MEDIA_SCAN_ERROR__"
_SUMMARY_MARKER = "__KILLCHAIN_MEDIA_SCAN_SUMMARY__"
_DEFAULT_MAX_FILES = 48
_DEFAULT_MAX_EXTRACT_MB = 32
_MEDIA_SCAN_PY = r'''
import hashlib
import os
import re
import struct
import sys
from pathlib import Path

MEDIA = "__KILLCHAIN_MEDIA_SCAN_FILE__"
ARTIFACT = "__KILLCHAIN_MEDIA_SCAN_ARTIFACT__"
ERROR = "__KILLCHAIN_MEDIA_SCAN_ERROR__"
SUMMARY = "__KILLCHAIN_MEDIA_SCAN_SUMMARY__"
PNG_SIG = b"\x89PNG\r\n\x1a\n"
KEYWORDS = ("flag", "ctf", "key", "secret", "token", "password", "pearl")

def clean(value, limit=500):
    return re.sub(r"\s+", " ", str(value).replace("\t", " ").replace("\n", " ")).strip()[:limit]

def safe_name(value):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))[:80].strip("._") or "media"

def printable_preview(blob, limit=220):
    return clean("".join(chr(b) if b in b"\r\n\t" or 32 <= b < 127 else "." for b in blob[:limit]), limit)

def string_hits(blob, limit=8):
    text = "".join(chr(b) if 32 <= b < 127 else "\n" for b in blob[:250000])
    hits = []
    for part in re.split(r"\n+", text):
        if len(part) < 4:
            continue
        lower = part.lower()
        if any(keyword in lower for keyword in KEYWORDS):
            if part not in hits:
                hits.append(clean(part, 180))
        if len(hits) >= limit:
            break
    return hits

def png_end_and_meta(data):
    if not data.startswith(PNG_SIG):
        return None, {}
    pos = len(PNG_SIG)
    chunks = 0
    width = height = 0
    texts = []
    while pos + 8 <= len(data) and chunks < 512:
        length = int.from_bytes(data[pos:pos + 4], "big")
        ctype = data[pos + 4:pos + 8].decode("latin1", "replace")
        start = pos + 8
        end = start + length
        crc_end = end + 4
        if crc_end > len(data):
            return None, {"kind": "png", "chunks": chunks, "truncated": True}
        payload = data[start:end]
        if ctype == "IHDR" and len(payload) >= 8:
            width, height = struct.unpack(">II", payload[:8])
        if ctype in {"tEXt", "zTXt", "iTXt"}:
            texts.append(printable_preview(payload, 160))
        chunks += 1
        pos = crc_end
        if ctype == "IEND":
            return pos, {
                "kind": "png",
                "width": width,
                "height": height,
                "chunks": chunks,
                "text": " | ".join(texts[:4]),
            }
    return None, {"kind": "png", "chunks": chunks, "truncated": True}

def media_end_and_meta(data, path):
    lower = path.name.lower()
    png_end, png_meta = png_end_and_meta(data)
    if png_meta:
        return png_end, png_meta
    if data.startswith((b"GIF87a", b"GIF89a")):
        end = data.rfind(b"\x3b")
        width = height = 0
        if len(data) >= 10:
            width, height = struct.unpack("<HH", data[6:10])
        return (end + 1 if end >= 0 else None), {
            "kind": "gif",
            "width": width,
            "height": height,
        }
    if data.startswith(b"\xff\xd8"):
        end = data.rfind(b"\xff\xd9")
        return (end + 2 if end >= 0 else None), {"kind": "jpeg"}
    if b"ftyp" in data[:64] or lower.endswith((".mp4", ".mov", ".m4v")):
        return None, {"kind": "mp4"}
    if lower.endswith((".wav", ".mp3", ".avi", ".bmp", ".tif", ".tiff")):
        return None, {"kind": lower.rsplit(".", 1)[-1]}
    return None, {"kind": "unknown"}

def write_artifact(out_root, source, payload, budget):
    if not payload or budget["count"] >= 32:
        return ""
    size = len(payload)
    if size > budget["remaining"]:
        return ""
    name = safe_name(source.name) + "_appended.bin"
    dest = out_root / name
    suffix = 1
    while dest.exists():
        dest = out_root / f"{safe_name(source.name)}_appended_{suffix}.bin"
        suffix += 1
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(payload)
    budget["remaining"] -= size
    budget["count"] += 1
    digest = hashlib.sha256(payload).hexdigest()
    print(f"{ARTIFACT}\t{dest}\t{size}\tappended\t{clean(str(source))}\t{digest}")
    return str(dest)

def inspect_one(path, out_root, budget):
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"{ERROR}\t{clean(str(path))}\t{clean(exc)}")
        return 0, 0
    end, meta = media_end_and_meta(data, path)
    kind = meta.get("kind", "unknown")
    appended = b""
    if end is not None and 0 <= end < len(data):
        appended = data[end:]
    artifact = ""
    if len(appended) >= 8:
        artifact = write_artifact(out_root, path, appended, budget)
    hits = string_hits(data)
    if appended:
        for hit in string_hits(appended):
            if hit not in hits:
                hits.append(hit)
            if len(hits) >= 10:
                break
    suspicious = int(bool(artifact or hits or meta.get("text") or meta.get("truncated")))
    details = []
    for key in ("width", "height", "chunks", "truncated", "text"):
        if key in meta and meta[key] not in (None, "", 0, False):
            details.append(f"{key}={clean(meta[key], 160)}")
    print(
        f"{MEDIA}\t{path}\t{len(data)}\t{kind}\t{suspicious}\t{len(appended)}\t"
        f"{artifact}\t{clean(' | '.join(hits), 700)}\t{clean('; '.join(details), 500)}"
    )
    return 1, suspicious

def main():
    out_root = Path(sys.argv[1])
    max_files = int(sys.argv[2])
    max_extract_mb = int(sys.argv[3])
    paths = [Path(arg) for arg in sys.argv[4:]][:max_files]
    out_root.mkdir(parents=True, exist_ok=True)
    budget = {"remaining": max_extract_mb * 1024 * 1024, "count": 0}
    inspected = suspicious = 0
    for path in paths:
        one, flagged = inspect_one(path, out_root, budget)
        inspected += one
        suspicious += flagged
    print(f"{SUMMARY}\t{inspected}\t{suspicious}\t{budget['count']}")

if __name__ == "__main__":
    main()
'''


class MediaScanPlugin:
    name = "media_scan"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        paths = _paths_from_metadata(request.metadata)
        max_files = _positive_int(request.metadata.get("max_files"), _DEFAULT_MAX_FILES)
        max_extract_mb = _positive_int(
            request.metadata.get("max_extract_mb"),
            _DEFAULT_MAX_EXTRACT_MB,
        )
        output_expr = _durable_output_expr(files_root)
        args = " ".join(shlex.quote(path) for path in paths)
        cmd = (
            f"_kc_out={output_expr}; "
            f"python3 -c {shlex.quote(_MEDIA_SCAN_PY)} "
            f'"$_kc_out" {max_files} {max_extract_mb} {args}'
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
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    records = _parse_records(stdout)
    artifacts = [
        Artifact(
            path=record["path"],
            kind=f"media_scan_{record.get('role') or 'artifact'}",
            source="media_scan",
            size=record.get("size"),
            digest=record.get("digest"),
            metadata={"source_file": record.get("source_file")},
        )
        for record in records["artifacts"][:80]
    ]
    flags = _flag_candidates_from(
        "\n".join(
            str(item.get("strings") or "")
            for item in records["media"]
            if item.get("strings")
        ),
        source="media_scan",
    )
    suspicious_count = sum(1 for item in records["media"] if item.get("suspicious"))
    appended_count = sum(1 for item in records["media"] if item.get("appended_size"))
    summary = (
        f"media.scan: {len(records['media'])} file(s) inspected, "
        f"{suspicious_count} suspicious, {appended_count} appended payload(s)"
    )
    if records["artifacts"]:
        summary += f", {len(records['artifacts'])} artifact(s)"
    if flags:
        summary += f" - {len(flags)} flag candidate(s)"
    if records["errors"]:
        summary += f", {len(records['errors'])} error(s)"
    return ToolOutput(
        status=_status(result),
        summary=summary,
        output_text=_truncate(stdout, 5000),
        raw_log=_truncate(stdout + stderr, 7000),
        output_context={
            "media": records["media"][:80],
            "artifact_records": records["artifacts"][:80],
            "errors": records["errors"][:20],
            "extracted_artifacts_durable": True,
        },
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _paths_from_metadata(metadata: dict[str, object]) -> list[str]:
    raw = metadata.get("paths")
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    path = str(metadata.get("path") or metadata.get("artifact_path") or "").strip()
    return [path] if path else []


def _durable_output_expr(files_root: str) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    return f'"{root}/.autopentest_artifacts/media_scan_$$"'


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _parse_records(stdout: str) -> dict[str, list[dict[str, Any]]]:
    records: dict[str, list[dict[str, Any]]] = {
        "media": [],
        "artifacts": [],
        "errors": [],
    }
    for line in stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        marker = parts[0]
        if marker == _MEDIA_MARKER and len(parts) >= 9:
            records["media"].append({
                "path": parts[1],
                "size": _int_or_none(parts[2]),
                "kind": parts[3],
                "suspicious": parts[4] == "1",
                "appended_size": _int_or_none(parts[5]),
                "artifact_path": parts[6] or None,
                "strings": parts[7],
                "details": parts[8],
            })
        elif marker == _ARTIFACT_MARKER and len(parts) >= 6:
            records["artifacts"].append({
                "path": parts[1],
                "size": _int_or_none(parts[2]),
                "role": parts[3],
                "source_file": parts[4],
                "digest": parts[5],
            })
        elif marker == _ERROR_MARKER and len(parts) >= 3:
            records["errors"].append({"path": parts[1], "detail": parts[2]})
    return records


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


__all__ = [
    "MediaScanPlugin",
    "_ARTIFACT_MARKER",
    "_ERROR_MARKER",
    "_MEDIA_MARKER",
    "_SUMMARY_MARKER",
    "build_output",
]
