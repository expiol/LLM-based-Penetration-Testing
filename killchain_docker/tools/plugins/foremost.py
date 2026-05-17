"""foremost — file carving from disk images or binary blobs.

Supports:
  - Automatic file type carving (images, documents, archives, etc.)
  - Rich output parsing: carved file types, counts, audit.txt parsing
  - Typed state signals: Artifact per carved file
"""

from __future__ import annotations

import re
from typing import Any

from killchain_docker.state import Artifact
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


# audit.txt line: "Num  Name (bs=512)      Size  File Offset  Comment"
_AUDIT_RE = re.compile(r"^\d+:\s+(\S+)\s+(\d+)\s+(\d+)", re.MULTILINE)


class ForemostPlugin:
    name = "foremost"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        output_dir = str(request.metadata.get("output_dir") or "/tmp/foremost_out")
        cmd = (
            f"foremost -i {path} -o {output_dir} -T && "
            f"find {output_dir} -type f | head -80 && "
            f"cat {output_dir}/*/audit.txt 2>/dev/null || true"
        )
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)

    # -- Parse carved files from find output --------------------------------
    carved_files: list[str] = []
    for line in stdout.splitlines():
        line_s = line.strip()
        if line_s and "/" in line_s and not line_s.startswith("Foremost") and "audit.txt" not in line_s:
            carved_files.append(line_s)

    # -- Categorize by extension --------------------------------------------
    type_counts: dict[str, int] = {}
    for fpath in carved_files:
        ext = fpath.rsplit(".", 1)[-1].lower() if "." in fpath else "unknown"
        # Group by directory name (foremost organizes by type)
        parts = fpath.split("/")
        for part in parts:
            if part in ("jpg", "png", "gif", "bmp", "pdf", "doc", "zip", "rar",
                        "exe", "elf", "htm", "ole", "all"):
                ext = part
                break
        type_counts[ext] = type_counts.get(ext, 0) + 1

    # -- Artifacts -----------------------------------------------------------
    artifacts: list[Artifact] = []
    for fpath in carved_files[:50]:
        ext = fpath.rsplit(".", 1)[-1].lower() if "." in fpath else "unknown"
        artifacts.append(Artifact(
            path=fpath,
            kind=f"foremost_{ext}",
            source="foremost",
            metadata={"source_file": path},
        ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="foremost")

    # -- Summary -------------------------------------------------------------
    summary = f"foremost {path}: {len(carved_files)} file(s) carved"
    if type_counts:
        type_parts = [f"{count} {kind}" for kind, count in
                      sorted(type_counts.items(), key=lambda x: -x[1])[:4]]
        summary += f" ({', '.join(type_parts)})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "carved_count": len(carved_files),
        "carved_files": carved_files[:50],
    }
    if type_counts:
        output_context["type_counts"] = type_counts

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
