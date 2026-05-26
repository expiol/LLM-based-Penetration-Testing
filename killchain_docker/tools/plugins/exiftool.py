"""exiftool — metadata extraction from files.

Supports:
  - Full EXIF/XMP/IPTC metadata extraction
  - Rich output parsing: hidden comments, GPS, camera info, software
  - Typed state signals: Artifact with classified metadata
"""

from __future__ import annotations
import re
from typing import Any
from killchain_docker.state.domain import Artifact
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

_INTERESTING_KEYS = frozenset(
    {
        "comment",
        "user comment",
        "artist",
        "author",
        "description",
        "subject",
        "title",
        "copyright",
        "xp comment",
        "xp keywords",
        "image description",
        "special instructions",
        "warning",
        "gps latitude",
        "gps longitude",
        "gps position",
        "software",
        "creator tool",
        "producer",
    }
)


class ExiftoolPlugin:
    name = "exiftool"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"exiftool {path}"],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    all_meta: dict[str, str] = {}
    for line in stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            all_meta[k.strip()] = v.strip()
    interesting: dict[str, str] = {}
    for key, value in all_meta.items():
        if key.lower() in _INTERESTING_KEYS and value:
            interesting[key] = value
    file_type = all_meta.get("File Type", all_meta.get("MIME Type", ""))
    file_size = all_meta.get("File Size", "")
    image_size = all_meta.get("Image Size", "")
    gps_lat = all_meta.get("GPS Latitude", "")
    gps_lon = all_meta.get("GPS Longitude", "")
    software = all_meta.get("Software", all_meta.get("Creator Tool", ""))
    camera = all_meta.get("Camera Model Name", all_meta.get("Model", ""))
    artifacts: list[Artifact] = []
    if path:
        meta: dict[str, Any] = {"field_count": len(all_meta)}
        if file_type:
            meta["file_type"] = file_type
        if image_size:
            meta["image_size"] = image_size
        if software:
            meta["software"] = software
        if camera:
            meta["camera"] = camera
        if gps_lat and gps_lon:
            meta["gps"] = {"latitude": gps_lat, "longitude": gps_lon}
        artifacts.append(
            Artifact(
                path=path,
                kind="media" if image_size else "unknown",
                source="exiftool",
                metadata=meta,
            )
        )
    flags = _flag_candidates_from(stdout, source="exiftool")
    for value in interesting.values():
        flags.extend(_flag_candidates_from(value, source="exiftool"))
    summary = f"exiftool {path}: {len(all_meta)} field(s)"
    if interesting:
        summary += f", {len(interesting)} interesting"
    if gps_lat:
        summary += " [GPS]"
    if file_type:
        summary += f" [{file_type}]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "metadata": {k: v for k, v in list(all_meta.items())[:40]},
    }
    if interesting:
        output_context["interesting_fields"] = interesting
    if gps_lat and gps_lon:
        output_context["gps"] = {"latitude": gps_lat, "longitude": gps_lon}
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 4000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
