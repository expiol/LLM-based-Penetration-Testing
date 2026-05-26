"""gdb — debugging and dynamic analysis.

Supports:
  - Batch command execution (info functions, break, run, bt, x/...)
  - Rich output parsing: function list, register values, memory dumps
  - Typed state signals: Artifact for analyzed binary
"""

from __future__ import annotations
import re
import shlex
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
from killchain_docker.tools.plugins.workspace import protected_shell_command

_FUNC_RE = re.compile("(0x[0-9a-fA-F]+)\\s+(\\S+)")
_REG_RE = re.compile(
    "^(e?[a-z]{2,3}|r[a-z0-9]{1,3})\\s+(0x[0-9a-fA-F]+)\\s+", re.MULTILINE
)
_SIGNAL_RE = re.compile("Program received signal (\\S+)", re.IGNORECASE)
_BT_RE = re.compile("#(\\d+)\\s+(0x[0-9a-fA-F]+)\\s+in\\s+(\\S+)")


class GdbPlugin:
    name = "gdb"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        cmds = str(request.metadata.get("commands") or "info functions")
        files_root = request.metadata.get("files_root")
        full_cmd = (
            f"printf '%s\\n' {shlex.quote(cmds)} | gdb -batch -q {shlex.quote(path)}"
        )
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(full_cmd, files_root),
            ],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    cmds = str(request.metadata.get("commands") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    functions: list[dict[str, str]] = []
    in_func_section = False
    for line in stdout.splitlines():
        if "All defined functions" in line or "Non-debugging symbols" in line:
            in_func_section = True
            continue
        if in_func_section:
            m = _FUNC_RE.match(line.strip())
            if m:
                functions.append({"address": m.group(1), "name": m.group(2)})
    registers: dict[str, str] = {}
    for m in _REG_RE.finditer(stdout):
        registers[m.group(1)] = m.group(2)
    signal = ""
    m = _SIGNAL_RE.search(stdout)
    if m:
        signal = m.group(1)
    backtrace: list[dict[str, str]] = []
    for m in _BT_RE.finditer(stdout):
        backtrace.append(
            {"frame": m.group(1), "address": m.group(2), "function": m.group(3)}
        )
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(
            Artifact(
                path=path,
                kind="binary",
                source="gdb",
                metadata={"commands": cmds[:200]},
            )
        )
    flags = _flag_candidates_from(stdout, source="gdb")
    summary = f"gdb {path}: '{cmds[:50]}'"
    if functions:
        summary += f", {len(functions)} function(s)"
    if signal:
        summary += f" — {signal}"
    if backtrace:
        summary += f", {len(backtrace)} frame(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {"path": path, "commands": cmds}
    if functions:
        output_context["functions"] = functions[:30]
    if registers:
        output_context["registers"] = registers
    if signal:
        output_context["signal"] = signal
    if backtrace:
        output_context["backtrace"] = backtrace[:20]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
