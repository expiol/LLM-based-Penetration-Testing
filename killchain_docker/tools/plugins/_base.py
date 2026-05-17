"""Shared base for all tool plugins.

Provides:
  - _run(): unified subprocess execution with timeout handling
  - _require(): metadata field validation
  - _status(): exit code → ToolOutputStatus
  - _flag_candidates_from(): stdout flag extraction
  - _truncate, extract_flags_from_text: re-exports from core
"""

from __future__ import annotations

import subprocess
from typing import Any

from killchain_docker.state import FlagCandidate
from killchain_docker.state.constants import validatable_flag_candidate
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    ParsedToolOutput,
    extract_flags_from_text,
    _truncate,
)


def _run(
    name: str,
    argv: list[str],
    timeout_s: int,
    *,
    cwd: str | None = None,
) -> ToolExecutionResult:
    """Shared subprocess runner for all plugins."""
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout_s, check=False, cwd=cwd,
        )
    except OSError as exc:
        raise ToolExecutionError(f"{name} failed: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        stdout = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else str(exc.stdout or "")
        stderr = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else str(exc.stderr or "")
        return ToolExecutionResult(
            tool_name=name, mode=ExecutionMode.LOCAL_COMMAND, exit_code=-1,
            stdout=stdout, stderr=f"{stderr}\n[timeout after {timeout_s}s]",
        )
    return ToolExecutionResult(
        tool_name=name, mode=ExecutionMode.LOCAL_COMMAND,
        exit_code=completed.returncode,
        stdout=completed.stdout, stderr=completed.stderr,
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
    raw = extract_flags_from_text(text)
    return [
        FlagCandidate(value=v, source=source, confidence=0.6)
        for v in raw if validatable_flag_candidate(v)
    ]


def _err_tail(stderr: str) -> str:
    lines = [l.strip() for l in stderr.splitlines() if l.strip()]
    return lines[-1][:200] if lines else ""
