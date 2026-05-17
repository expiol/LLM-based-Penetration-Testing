"""binwalk — firmware/binary analysis and extraction.

Supports:
  - Signature scanning to identify embedded file types
  - Extraction mode to carve embedded files
  - Rich output parsing: signature types, offsets, extracted files
  - Typed state signals: Artifact per detected/extracted embedded file
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


# Binwalk output line: "DECIMAL    HEXADECIMAL    DESCRIPTION"
_SIG_RE = re.compile(r"^(\d+)\s+(0x[0-9A-Fa-f]+)\s+(.+)$", re.MULTILINE)


class BinwalkPlugin:
    name = "binwalk"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        extract = request.metadata.get("extract", False)
        extract_flag = "-e --directory=/tmp/binwalk_out" if extract else ""
        cmd = f"binwalk {extract_flag} {path}"
        if extract:
            cmd += f" && find /tmp/binwalk_out -type f 2>/dev/null | head -50"
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    extract = bool(request.metadata.get("extract", False))
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)

    # -- Parse signatures ----------------------------------------------------
    signatures: list[dict[str, Any]] = []
    for m in _SIG_RE.finditer(stdout):
        offset = int(m.group(1))
        hex_offset = m.group(2)
        description = m.group(3).strip()
        signatures.append({
            "offset": offset,
            "hex_offset": hex_offset,
            "description": description,
        })

    # -- Parse extracted files (from find output after extraction) -----------
    extracted_files: list[str] = []
    if extract:
        in_find_output = False
        for line in stdout.splitlines():
            line_s = line.strip()
            # After binwalk output, find results appear
            if line_s.startswith("/tmp/binwalk_out"):
                in_find_output = True
                extracted_files.append(line_s)
            elif in_find_output and line_s and not _SIG_RE.match(line_s):
                extracted_files.append(line_s)

    # -- Categorize signatures -----------------------------------------------
    sig_types: dict[str, int] = {}
    for sig in signatures:
        desc_lower = sig["description"].lower()
        if "zip" in desc_lower:
            sig_types["zip"] = sig_types.get("zip", 0) + 1
        elif "gzip" in desc_lower:
            sig_types["gzip"] = sig_types.get("gzip", 0) + 1
        elif "elf" in desc_lower:
            sig_types["elf"] = sig_types.get("elf", 0) + 1
        elif "png" in desc_lower or "jpeg" in desc_lower or "image" in desc_lower:
            sig_types["image"] = sig_types.get("image", 0) + 1
        elif "filesystem" in desc_lower or "squashfs" in desc_lower or "cramfs" in desc_lower:
            sig_types["filesystem"] = sig_types.get("filesystem", 0) + 1
        elif "certificate" in desc_lower or "ssl" in desc_lower:
            sig_types["certificate"] = sig_types.get("certificate", 0) + 1

    # -- Artifacts -----------------------------------------------------------
    artifacts: list[Artifact] = []
    for fpath in extracted_files[:30]:
        artifacts.append(Artifact(
            path=fpath,
            kind="binwalk_extract",
            source="binwalk",
            metadata={"source_file": path},
        ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="binwalk")

    # -- Summary -------------------------------------------------------------
    summary = f"binwalk {path}: {len(signatures)} signature(s)"
    if sig_types:
        type_parts = [f"{count} {kind}" for kind, count in sorted(sig_types.items(), key=lambda x: -x[1])[:4]]
        summary += f" ({', '.join(type_parts)})"
    if extracted_files:
        summary += f", {len(extracted_files)} file(s) extracted"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "signature_count": len(signatures),
        "signatures": signatures[:20],
    }
    if sig_types:
        output_context["signature_types"] = sig_types
    if extracted_files:
        output_context["extracted_files"] = extracted_files[:30]

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
