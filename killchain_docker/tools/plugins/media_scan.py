"""media.scan - deterministic batch inspection for embedded media files."""

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
from killchain_docker.tools.plugins.workspace import protected_shell_command

_MEDIA_MARKER = "__KILLCHAIN_MEDIA_SCAN_FILE__"
_ARTIFACT_MARKER = "__KILLCHAIN_MEDIA_SCAN_ARTIFACT__"
_ERROR_MARKER = "__KILLCHAIN_MEDIA_SCAN_ERROR__"
_SUMMARY_MARKER = "__KILLCHAIN_MEDIA_SCAN_SUMMARY__"
_DEFAULT_MAX_FILES = 48
_DEFAULT_MAX_EXTRACT_MB = 32
_MEDIA_SCAN_PY = '\nimport hashlib\nimport os\nimport re\nimport struct\nimport sys\nfrom pathlib import Path\n\nMEDIA = "__KILLCHAIN_MEDIA_SCAN_FILE__"\nARTIFACT = "__KILLCHAIN_MEDIA_SCAN_ARTIFACT__"\nERROR = "__KILLCHAIN_MEDIA_SCAN_ERROR__"\nSUMMARY = "__KILLCHAIN_MEDIA_SCAN_SUMMARY__"\nPNG_SIG = b"\\x89PNG\\r\\n\\x1a\\n"\nKEYWORDS = ("flag", "ctf", "key", "secret", "token", "password", "pearl")\n\ndef clean(value, limit=500):\n    return re.sub(r"\\s+", " ", str(value).replace("\\t", " ").replace("\\n", " ")).strip()[:limit]\n\ndef safe_name(value):\n    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value))[:80].strip("._") or "media"\n\ndef printable_preview(blob, limit=220):\n    return clean("".join(chr(b) if b in b"\\r\\n\\t" or 32 <= b < 127 else "." for b in blob[:limit]), limit)\n\ndef string_hits(blob, limit=8):\n    text = "".join(chr(b) if 32 <= b < 127 else "\\n" for b in blob[:250000])\n    hits = []\n    for part in re.split(r"\\n+", text):\n        if len(part) < 4:\n            continue\n        lower = part.lower()\n        if any(keyword in lower for keyword in KEYWORDS):\n            if part not in hits:\n                hits.append(clean(part, 180))\n        if len(hits) >= limit:\n            break\n    return hits\n\ndef png_end_and_meta(data):\n    if not data.startswith(PNG_SIG):\n        return None, {}\n    pos = len(PNG_SIG)\n    chunks = 0\n    width = height = 0\n    texts = []\n    while pos + 8 <= len(data) and chunks < 512:\n        length = int.from_bytes(data[pos:pos + 4], "big")\n        ctype = data[pos + 4:pos + 8].decode("latin1", "replace")\n        start = pos + 8\n        end = start + length\n        crc_end = end + 4\n        if crc_end > len(data):\n            return None, {"kind": "png", "chunks": chunks, "truncated": True}\n        payload = data[start:end]\n        if ctype == "IHDR" and len(payload) >= 8:\n            width, height = struct.unpack(">II", payload[:8])\n        if ctype in {"tEXt", "zTXt", "iTXt"}:\n            texts.append(printable_preview(payload, 160))\n        chunks += 1\n        pos = crc_end\n        if ctype == "IEND":\n            return pos, {\n                "kind": "png",\n                "width": width,\n                "height": height,\n                "chunks": chunks,\n                "text": " | ".join(texts[:4]),\n            }\n    return None, {"kind": "png", "chunks": chunks, "truncated": True}\n\ndef media_end_and_meta(data, path):\n    lower = path.name.lower()\n    png_end, png_meta = png_end_and_meta(data)\n    if png_meta:\n        return png_end, png_meta\n    if data.startswith((b"GIF87a", b"GIF89a")):\n        end = data.rfind(b"\\x3b")\n        width = height = 0\n        if len(data) >= 10:\n            width, height = struct.unpack("<HH", data[6:10])\n        return (end + 1 if end >= 0 else None), {\n            "kind": "gif",\n            "width": width,\n            "height": height,\n        }\n    if data.startswith(b"\\xff\\xd8"):\n        end = data.rfind(b"\\xff\\xd9")\n        return (end + 2 if end >= 0 else None), {"kind": "jpeg"}\n    if b"ftyp" in data[:64] or lower.endswith((".mp4", ".mov", ".m4v")):\n        return None, {"kind": "mp4"}\n    if lower.endswith((".wav", ".mp3", ".avi", ".bmp", ".tif", ".tiff")):\n        return None, {"kind": lower.rsplit(".", 1)[-1]}\n    return None, {"kind": "unknown"}\n\ndef write_artifact(out_root, source, payload, budget):\n    if not payload or budget["count"] >= 32:\n        return ""\n    size = len(payload)\n    if size > budget["remaining"]:\n        return ""\n    name = safe_name(source.name) + "_appended.bin"\n    dest = out_root / name\n    suffix = 1\n    while dest.exists():\n        dest = out_root / f"{safe_name(source.name)}_appended_{suffix}.bin"\n        suffix += 1\n    dest.parent.mkdir(parents=True, exist_ok=True)\n    dest.write_bytes(payload)\n    budget["remaining"] -= size\n    budget["count"] += 1\n    digest = hashlib.sha256(payload).hexdigest()\n    print(f"{ARTIFACT}\\t{dest}\\t{size}\\tappended\\t{clean(str(source))}\\t{digest}")\n    return str(dest)\n\ndef inspect_one(path, out_root, budget):\n    try:\n        data = path.read_bytes()\n    except OSError as exc:\n        print(f"{ERROR}\\t{clean(str(path))}\\t{clean(exc)}")\n        return 0, 0\n    end, meta = media_end_and_meta(data, path)\n    kind = meta.get("kind", "unknown")\n    appended = b""\n    if end is not None and 0 <= end < len(data):\n        appended = data[end:]\n    artifact = ""\n    if len(appended) >= 8:\n        artifact = write_artifact(out_root, path, appended, budget)\n    hits = string_hits(data)\n    if appended:\n        for hit in string_hits(appended):\n            if hit not in hits:\n                hits.append(hit)\n            if len(hits) >= 10:\n                break\n    suspicious = int(bool(artifact or hits or meta.get("text") or meta.get("truncated")))\n    details = []\n    for key in ("width", "height", "chunks", "truncated", "text"):\n        if key in meta and meta[key] not in (None, "", 0, False):\n            details.append(f"{key}={clean(meta[key], 160)}")\n    print(\n        f"{MEDIA}\\t{path}\\t{len(data)}\\t{kind}\\t{suspicious}\\t{len(appended)}\\t"\n        f"{artifact}\\t{clean(\' | \'.join(hits), 700)}\\t{clean(\'; \'.join(details), 500)}"\n    )\n    return 1, suspicious\n\ndef main():\n    out_root = Path(sys.argv[1])\n    max_files = int(sys.argv[2])\n    max_extract_mb = int(sys.argv[3])\n    paths = [Path(arg) for arg in sys.argv[4:]][:max_files]\n    out_root.mkdir(parents=True, exist_ok=True)\n    budget = {"remaining": max_extract_mb * 1024 * 1024, "count": 0}\n    inspected = suspicious = 0\n    for path in paths:\n        one, flagged = inspect_one(path, out_root, budget)\n        inspected += one\n        suspicious += flagged\n    print(f"{SUMMARY}\\t{inspected}\\t{suspicious}\\t{budget[\'count\']}")\n\nif __name__ == "__main__":\n    main()\n'


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
            request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB
        )
        output_expr = _durable_output_expr(files_root)
        args = " ".join((shlex.quote(path) for path in paths))
        cmd = f'_kc_out={output_expr}; python3 -c {shlex.quote(_MEDIA_SCAN_PY)} "$_kc_out" {max_files} {max_extract_mb} {args}'
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
            (
                str(item.get("strings") or "")
                for item in records["media"]
                if item.get("strings")
            )
        ),
        source="media_scan",
    )
    suspicious_count = sum((1 for item in records["media"] if item.get("suspicious")))
    appended_count = sum((1 for item in records["media"] if item.get("appended_size")))
    summary = f"media.scan: {len(records['media'])} file(s) inspected, {suspicious_count} suspicious, {appended_count} appended payload(s)"
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
            records["media"].append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "kind": parts[3],
                    "suspicious": parts[4] == "1",
                    "appended_size": _int_or_none(parts[5]),
                    "artifact_path": parts[6] or None,
                    "strings": parts[7],
                    "details": parts[8],
                }
            )
        elif marker == _ARTIFACT_MARKER and len(parts) >= 6:
            records["artifacts"].append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "role": parts[3],
                    "source_file": parts[4],
                    "digest": parts[5],
                }
            )
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
