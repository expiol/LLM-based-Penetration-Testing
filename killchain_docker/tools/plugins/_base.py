"""Shared base for all tool plugins.

Provides:
  - _run(): unified subprocess execution with timeout handling
  - _require(): metadata field validation
  - _status(): exit code → ToolOutputStatus
  - _flag_candidates_from(): stdout flag extraction
  - _truncate: re-export from core
"""

from __future__ import annotations

from typing import Any

from killchain_docker.processes import DEFAULT_MAX_CAPTURE_BYTES, run_bounded_process
from killchain_docker.reasoning.flag import extract_flag_candidates
from killchain_docker.state import FlagCandidate
from killchain_docker.state.constants import FLAG_PATTERN, validatable_flag_candidate
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    ParsedToolOutput,
    _truncate,
)

_MAX_CAPTURE_BYTES = DEFAULT_MAX_CAPTURE_BYTES


def _run(
    name: str,
    argv: list[str],
    timeout_s: int,
    *,
    cwd: str | None = None,
    input_text: str | None = None,
    max_output_bytes: int = _MAX_CAPTURE_BYTES,
) -> ToolExecutionResult:
    """Shared subprocess runner for all plugins."""
    try:
        result = run_bounded_process(
            argv,
            timeout_s=timeout_s,
            cwd=cwd,
            input_text=input_text,
            max_output_bytes=max_output_bytes,
        )
    except OSError as exc:
        raise ToolExecutionError(f"{name} failed: {exc}") from exc
    return ToolExecutionResult(
        tool_name=name,
        mode=ExecutionMode.LOCAL_COMMAND,
        exit_code=result.exit_code,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _require(metadata: dict[str, Any], key: str, plugin_name: str) -> str:
    """Extract a required string field from metadata or raise."""
    val = str(metadata.get(key) or "").strip()
    if not val:
        raise ToolExecutionError(f"{plugin_name} requires metadata.{key}")
    return val


def _status(result: ToolExecutionResult) -> ToolOutputStatus:
    if result.exit_code is not None and result.exit_code != 0:
        return ToolOutputStatus.FAILURE
    return ToolOutputStatus.SUCCESS


def _flag_candidates_from(text: str, *, source: str = "") -> list[FlagCandidate]:
    """Extract flag candidates from tool output text.

    Uses a two-tier confidence model:
      - 0.6: direct regex match (canonical ``prefix{body}`` in raw text)
      - 0.4: derived via encoding decode or bracket-span heuristic
    """
    if not text:
        return []

    # extract_flag_candidates handles the full pipeline: regex, base64/hex/rot13
    # decode, and bracket-span extraction — no need to call extract_flags_from_text
    # separately.
    all_values = extract_flag_candidates(text)

    # Direct regex hits get higher confidence than derived candidates.
    direct_hits = set(FLAG_PATTERN.findall(text))

    return [
        FlagCandidate(
            value=v,
            source=source,
            confidence=0.6 if v in direct_hits else 0.4,
        )
        for v in all_values
        if validatable_flag_candidate(v)
    ]


def _err_tail(stderr: str) -> str:
    lines = [l.strip() for l in stderr.splitlines() if l.strip()]
    return lines[-1][:200] if lines else ""
