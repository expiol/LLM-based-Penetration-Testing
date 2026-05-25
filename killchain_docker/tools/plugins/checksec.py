"""checksec — binary security properties analysis.

Supports:
  - NX, PIE, canary, RELRO, RPATH, RUNPATH, symbols, FORTIFY detection
  - Attack surface hints derived from protection status
  - Typed state signals: Artifact for analyzed binary
"""

from __future__ import annotations

import json
import re
from typing import Any

from killchain_docker.state import Artifact
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _truncate,
)

# Table-format parser regexes for checksec versions without JSON output.
_RELRO_RE = re.compile(r"(Full RELRO|Partial RELRO|No RELRO)", re.IGNORECASE)
_CANARY_RE = re.compile(r"(Canary found|No canary found)", re.IGNORECASE)
_NX_RE = re.compile(r"(NX enabled|NX disabled)", re.IGNORECASE)
_PIE_RE = re.compile(r"(PIE enabled|No PIE|DSO)", re.IGNORECASE)


class ChecksecPlugin:
    name = "checksec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"checksec --file={path} --output=json 2>/dev/null || checksec --file={path}"],
            request.timeout_s,
        )


def _parse_json_output(stdout: str, path: str) -> dict[str, Any] | None:
    """Try to parse checksec JSON output."""
    try:
        data = json.loads(stdout)
    except (json.JSONDecodeError, ValueError):
        return None
    # checksec JSON keys the result by file path
    if isinstance(data, dict):
        # Try exact path match or first key
        props = data.get(path) or next(iter(data.values()), None)
        if isinstance(props, dict):
            return props
    return None


def _parse_table_output(stdout: str) -> dict[str, Any]:
    """Parse checksec table output with regex."""
    props: dict[str, Any] = {}
    m = _RELRO_RE.search(stdout)
    if m:
        val = m.group(1).lower()
        props["relro"] = "full" if "full" in val else ("partial" if "partial" in val else "no")
    m = _CANARY_RE.search(stdout)
    if m:
        props["canary"] = "found" in m.group(1).lower()
    m = _NX_RE.search(stdout)
    if m:
        props["nx"] = "enabled" in m.group(1).lower()
    m = _PIE_RE.search(stdout)
    if m:
        val = m.group(1).lower()
        props["pie"] = "enabled" in val
    return props


def _normalize_props(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize raw checksec properties to consistent boolean/string values."""

    def _bool(val: Any) -> bool:
        if isinstance(val, bool):
            return val
        s = str(val).lower().strip()
        return s in {"yes", "true", "1", "found", "enabled"}

    def _relro(val: Any) -> str:
        s = str(val).lower().strip()
        if "full" in s:
            return "full"
        if "partial" in s:
            return "partial"
        return "no"

    return {
        "relro": _relro(raw.get("relro", "no")),
        "canary": _bool(raw.get("canary", False)),
        "nx": _bool(raw.get("nx", False)),
        "pie": _bool(raw.get("pie", False)),
        "rpath": _bool(raw.get("rpath", False)),
        "runpath": _bool(raw.get("runpath", False)),
        "symbols": _bool(raw.get("symbols", False)),
        "fortify": _bool(raw.get("fortify_source", raw.get("fortify", False))),
    }


def _attack_surface_hints(props: dict[str, Any]) -> list[str]:
    """Generate actionable hints from security properties."""
    hints: list[str] = []
    if props.get("nx"):
        hints.append("NX enabled: use ROP/ret2libc instead of shellcode")
    else:
        hints.append("NX disabled: shellcode injection is viable")
    if props.get("pie"):
        hints.append("PIE enabled: need address leak before exploitation")
    else:
        hints.append("No PIE: binary addresses are fixed, no leak needed")
    if props.get("canary"):
        hints.append("Stack canary present: need canary leak or format string to bypass")
    else:
        hints.append("No canary: buffer overflow directly controls return address")
    relro = props.get("relro", "no")
    if relro == "full":
        hints.append("Full RELRO: GOT is read-only, cannot overwrite GOT entries")
    elif relro == "partial":
        hints.append("Partial RELRO: GOT overwrite is possible")
    else:
        hints.append("No RELRO: GOT and .dtors are writable")
    return hints


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = "\n".join(part for part in (stdout, stderr) if part)

    # Determine status
    status = ToolOutputStatus.SUCCESS if result.exit_code in (None, 0) else ToolOutputStatus.FAILURE

    # Parse properties from JSON output or checksec's table format.
    raw_props = _parse_json_output(stdout, path)
    if raw_props is None:
        raw_props = _parse_table_output(combined)

    props = _normalize_props(raw_props) if raw_props else {}
    hints = _attack_surface_hints(props) if props else []

    # Artifact
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(Artifact(
            path=path, kind="binary", source="checksec",
            metadata=props,
        ))

    # Flag candidates (unlikely but consistent with other plugins)
    flags = _flag_candidates_from(combined, source="checksec")

    # Summary
    if props:
        parts = []
        if props.get("nx"):
            parts.append("NX")
        if props.get("pie"):
            parts.append("PIE")
        if props.get("canary"):
            parts.append("Canary")
        parts.append(f"RELRO:{props.get('relro', '?')}")
        summary = f"checksec {path}: {', '.join(parts)}"
    else:
        summary = f"checksec {path}: parse failed"
        status = ToolOutputStatus.FAILURE

    # output_context
    output_context: dict[str, Any] = {"path": path, **props}
    if hints:
        output_context["attack_surface_hints"] = hints

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(combined, 4000),
        raw_log=_truncate(combined, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
