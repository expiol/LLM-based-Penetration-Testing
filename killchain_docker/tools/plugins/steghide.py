"""steghide — steganography detection and extraction.

Supports:
  - Info mode: detect embedded data without extracting
  - Extract mode: extract hidden data with optional passphrase
  - Rich output parsing: embedded file info, capacity, encryption
  - Typed state signals: Artifact for extracted files
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


_EMBEDDED_FILE_RE = re.compile(r'embedded file "(.+?)"', re.IGNORECASE)
_CAPACITY_RE = re.compile(r"capacity:\s*(.+)", re.IGNORECASE)
_ENCRYPTION_RE = re.compile(r"encryption.*?:\s*(.+)", re.IGNORECASE)
_EXTRACTED_RE = re.compile(r'wrote extracted data to "(.+?)"', re.IGNORECASE)


class SteghidePlugin:
    name = "steghide"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        passphrase = str(request.metadata.get("passphrase") or "")
        action = str(request.metadata.get("action") or "info")
        if action == "extract":
            out_file = f"/tmp/steghide_{path.rsplit('/', 1)[-1]}.out"
            cmd = f"steghide extract -sf {path} -p '{passphrase}' -xf {out_file} -f && cat {out_file}"
        else:
            cmd = f"steghide info {path} -p '{passphrase}'"
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    action = str(request.metadata.get("action") or "info")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = stdout + "\n" + stderr
    status = _status(result)

    # -- Parse embedded file info -------------------------------------------
    embedded_files = _EMBEDDED_FILE_RE.findall(combined)
    has_embedded = bool(embedded_files) or "embedded file" in combined.lower()

    capacity = ""
    m = _CAPACITY_RE.search(combined)
    if m:
        capacity = m.group(1).strip()

    encryption = ""
    m = _ENCRYPTION_RE.search(combined)
    if m:
        encryption = m.group(1).strip()

    extracted_path = ""
    m = _EXTRACTED_RE.search(combined)
    if m:
        extracted_path = m.group(1).strip()

    # -- Artifacts -----------------------------------------------------------
    artifacts: list[Artifact] = []
    if extracted_path:
        artifacts.append(Artifact(
            path=extracted_path,
            kind="steghide_extract",
            source="steghide",
            metadata={"cover_file": path},
        ))
    for ef in embedded_files:
        if ef != extracted_path:
            artifacts.append(Artifact(
                path=ef,
                kind="steghide_embedded",
                source="steghide",
                metadata={"cover_file": path, "detected_only": action != "extract"},
            ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="steghide")

    # -- Summary -------------------------------------------------------------
    summary = f"steghide {action} {path}"
    if has_embedded:
        summary += f" — embedded data detected"
        if embedded_files:
            summary += f" ({', '.join(embedded_files[:3])})"
    if extracted_path:
        summary += f" → {extracted_path}"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "action": action,
        "has_embedded_data": has_embedded,
    }
    if embedded_files:
        output_context["embedded_files"] = embedded_files
    if capacity:
        output_context["capacity"] = capacity
    if encryption:
        output_context["encryption"] = encryption
    if extracted_path:
        output_context["extracted_path"] = extracted_path

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(combined, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
