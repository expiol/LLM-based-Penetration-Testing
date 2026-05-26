"""binwalk — firmware/binary analysis and extraction.

Supports:
  - Signature scanning to identify embedded file types
  - Extraction mode to carve embedded files
  - Rich output parsing: signature types, offsets, extracted files
  - Typed state signals: Artifact per detected/extracted embedded file
"""

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
    ToolOutputStatus,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command

_SIG_RE = re.compile("^(\\d+)\\s+(0x[0-9A-Fa-f]+)\\s+(.+)$", re.MULTILINE)
_DEFAULT_EXTRACT_MB = 256


class BinwalkPlugin:
    name = "binwalk"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        extract = request.metadata.get("extract", False)
        files_root = request.metadata.get("files_root") or DEFAULT_FILES_ROOT
        quoted_path = shlex.quote(path)
        cmd = f"binwalk {quoted_path}"
        if extract:
            max_mb = _positive_int(
                request.metadata.get("max_extract_mb"), _DEFAULT_EXTRACT_MB
            )
            cmd = _bounded_extract_command(quoted_path, max_mb=max_mb)
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", protected_shell_command(cmd, files_root)],
            request.timeout_s,
        )


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _bounded_extract_command(quoted_path: str, *, max_mb: int) -> str:
    budget_kb = max_mb * 1024
    return f'''_kc_bw_out="$CTF_TEMP_DIR/binwalk_out"; mkdir -p "$_kc_bw_out"; binwalk -e --run-as=root --directory="$_kc_bw_out" {quoted_path} & _kc_bw_pid=$!; _kc_bw_limited=0; while kill -0 "$_kc_bw_pid" 2>/dev/null; do _kc_bw_kb=$(du -sk "$_kc_bw_out" 2>/dev/null | awk '{{print $1 + 0}}'); if [ "$_kc_bw_kb" -gt {budget_kb} ]; then echo "[binwalk extraction budget exceeded: ${{_kc_bw_kb}}KB > {budget_kb}KB]" >&2; kill -TERM "$_kc_bw_pid" 2>/dev/null || true; sleep 1; kill -KILL "$_kc_bw_pid" 2>/dev/null || true; _kc_bw_limited=1; break; fi; sleep 1; done; wait "$_kc_bw_pid"; _kc_bw_rc=$?; if [ "$_kc_bw_limited" = 1 ]; then _kc_bw_rc=0; fi; find "$_kc_bw_out" -type f -printf "%p\\t%s\\n" 2>/dev/null | sort -k2,2nr | head -50; exit "$_kc_bw_rc"'''


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
    signatures: list[dict[str, Any]] = []
    for m in _SIG_RE.finditer(stdout):
        offset = int(m.group(1))
        hex_offset = m.group(2)
        description = m.group(3).strip()
        signatures.append(
            {"offset": offset, "hex_offset": hex_offset, "description": description}
        )
    extracted_files: list[str] = []
    if extract:
        for line in stdout.splitlines():
            line_s = line.strip()
            if "/binwalk_out/" in line_s:
                extracted_files.append(line_s.split("\t", 1)[0])
    if status == ToolOutputStatus.FAILURE and (signatures or extracted_files):
        status = ToolOutputStatus.SUCCESS
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
        elif (
            "filesystem" in desc_lower
            or "squashfs" in desc_lower
            or "cramfs" in desc_lower
        ):
            sig_types["filesystem"] = sig_types.get("filesystem", 0) + 1
        elif "certificate" in desc_lower or "ssl" in desc_lower:
            sig_types["certificate"] = sig_types.get("certificate", 0) + 1
    artifacts: list[Artifact] = []
    flags = _flag_candidates_from(stdout, source="binwalk")
    summary = f"binwalk {path}: {len(signatures)} signature(s)"
    if sig_types:
        type_parts = [
            f"{count} {kind}"
            for kind, count in sorted(sig_types.items(), key=lambda x: -x[1])[:4]
        ]
        summary += f" ({', '.join(type_parts)})"
    if extracted_files:
        summary += f", {len(extracted_files)} scratch file(s) extracted"
    extraction_budget_exceeded = "extraction budget exceeded" in stderr.lower()
    if extraction_budget_exceeded:
        summary += ", extraction capped"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "signature_count": len(signatures),
        "signatures": signatures[:20],
    }
    if sig_types:
        output_context["signature_types"] = sig_types
    if extracted_files:
        output_context["extracted_files"] = extracted_files[:30]
        output_context["extracted_files_ephemeral"] = True
    if extraction_budget_exceeded:
        output_context["extraction_budget_exceeded"] = True
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        notes=[
            "binwalk extraction ran in disposable scratch; rerun extraction in the same tool call before inspecting files."
        ]
        if extracted_files
        else [],
        flag_candidates=flags,
        artifacts=artifacts,
    )
