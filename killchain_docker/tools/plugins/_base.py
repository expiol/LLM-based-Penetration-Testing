"""Shared base for all tool plugins.

Provides:
  - _run(): unified subprocess execution with timeout handling
  - _require(): metadata field validation
  - _status(): exit code → ToolOutputStatus
  - _flag_candidates_from(): stdout flag extraction
"""

from __future__ import annotations
from typing import Any
from killchain_docker.processes import DEFAULT_MAX_CAPTURE_BYTES, run_bounded_process
from killchain_docker.reasoning.flag import extract_flag_candidates
from killchain_docker.state.domain import FlagCandidate
from killchain_docker.state.constants import (
    looks_like_escaped_byte_candidate,
    validatable_flag_candidate,
)
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    ParsedToolOutput,
)

_MAX_CAPTURE_BYTES = DEFAULT_MAX_CAPTURE_BYTES
_INFRASTRUCTURE_ERROR_NEEDLES = (
    "error response from daemon",
    "no such container",
    "container is not running",
    "cannot connect to the docker daemon",
    "docker daemon",
)
_FLAG_SCAN_HEAD_CHARS = 80000
_FLAG_SCAN_TAIL_CHARS = 80000
_FLAG_SCAN_CONTEXT_CHARS = 4000
_FLAG_SCAN_MAX_WINDOWS = 32
_FLAG_SCAN_NEEDLES = (
    "flag",
    "candidate",
    "found",
    "recovered",
    "secret",
    "key",
    "plaintext",
    "decrypted",
    "decoded",
)


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


def _infrastructure_failure_signal(
    stdout: str, stderr: str, exit_code: int | None
) -> tuple[str, str] | None:
    text = "\n".join((part for part in (stderr, stdout) if part)).lower()
    if exit_code == 137:
        return (
            "infrastructure_error",
            "tool execution container was terminated by the runtime",
        )
    if any((needle in text for needle in _INFRASTRUCTURE_ERROR_NEEDLES)) or (
        "container " in text and " is not running" in text
    ):
        return (
            "infrastructure_error",
            "tool execution failed because the runtime container was unavailable",
        )
    return None


def _flag_candidates_from(text: str, *, source: str = "") -> list[FlagCandidate]:
    """Extract flag candidates from tool output text.

    Uses a two-tier confidence model:
      - 0.6: direct regex match (canonical ``prefix{body}`` in raw text)
      - 0.4: derived via encoding decode or bracket-span heuristic
    """
    if not text:
        return []
    scan_text = _flag_scan_text(text)
    all_values = extract_flag_candidates(scan_text)
    return [
        FlagCandidate(value=v, source=source, confidence=0.6 if v in text else 0.4)
        for v in all_values
        if validatable_flag_candidate(v) and (not looks_like_escaped_byte_candidate(v))
    ]


def _flag_scan_text(text: str) -> str:
    """Return bounded stdout/stderr slices used for candidate extraction.

    Tool execution already captures bounded output.  Candidate extraction keeps
    the same Codex-style discipline: inspect a deterministic head/tail sample
    plus small windows around flag-related words, never an unbounded blob.
    """
    if len(text) <= _FLAG_SCAN_HEAD_CHARS + _FLAG_SCAN_TAIL_CHARS:
        return text
    chunks = [text[:_FLAG_SCAN_HEAD_CHARS], text[-_FLAG_SCAN_TAIL_CHARS:]]
    lowered = text.lower()
    seen_offsets: set[int] = set()
    for needle in _FLAG_SCAN_NEEDLES:
        start = 0
        while len(seen_offsets) < _FLAG_SCAN_MAX_WINDOWS:
            index = lowered.find(needle, start)
            if index < 0:
                break
            window_start = max(0, index - _FLAG_SCAN_CONTEXT_CHARS // 2)
            window_end = min(len(text), index + _FLAG_SCAN_CONTEXT_CHARS // 2)
            offset_key = window_start // _FLAG_SCAN_CONTEXT_CHARS
            if offset_key not in seen_offsets:
                seen_offsets.add(offset_key)
                chunks.append(text[window_start:window_end])
            start = index + len(needle)
    return "\n".join(chunks)


def _err_tail(stderr: str) -> str:
    lines = [l.strip() for l in stderr.splitlines() if l.strip()]
    return lines[-1][:200] if lines else ""
