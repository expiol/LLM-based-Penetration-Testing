"""shell.exec — free-form shell execution inside the Docker container."""

from __future__ import annotations

from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ParsedToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _run,
    _status,
    _flag_candidates_from,
    _truncate,
    ToolExecutionError,
)


class ShellPlugin:
    """Execute an arbitrary shell command via ``bash -c``."""

    name = "shell_exec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        command = str(request.metadata.get("command") or "").strip()
        if not command:
            raise ToolExecutionError("shell.exec requires metadata.command")
        argv = [*self.argv_prefix, "bash", "-c", command]
        return _run(self.name, argv, request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    command = str(request.metadata.get("command") or "")[:200]
    status = _status(result)
    stdout, stderr = result.stdout or "", result.stderr or ""

    summary = f"shell: {command}"
    if status.value == "failure":
        summary = f"shell failed (exit {result.exit_code}): {command}"

    flags = _flag_candidates_from(stdout, source=f"shell:{command[:80]}")
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    return ToolOutput(
        status=status, summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        flag_candidates=flags,
    )
