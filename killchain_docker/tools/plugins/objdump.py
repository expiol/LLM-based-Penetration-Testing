"""objdump — disassembly and binary inspection.

Supports:
  - Intel/AT&T syntax disassembly, section headers, symbol tables
  - Rich output parsing: function detection, section info, instruction stats
  - Typed state signals: Artifact for analyzed binary
"""

from __future__ import annotations
import re
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

_FUNC_RE = re.compile("^([0-9a-fA-F]+)\\s+<(.+?)>:$", re.MULTILINE)
_SECTION_RE = re.compile(
    "^\\s*\\d+\\s+(\\.\\w+)\\s+([0-9a-fA-F]+)\\s+([0-9a-fA-F]+)", re.MULTILINE
)
_FORMAT_RE = re.compile("file format\\s+(.+)", re.IGNORECASE)


class ObjdumpPlugin:
    name = "objdump"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        flags_arg = str(request.metadata.get("flags") or "-d -M intel")
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"objdump {flags_arg} {path}"],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    functions: list[dict[str, str]] = []
    for m in _FUNC_RE.finditer(stdout):
        functions.append({"address": m.group(1), "name": m.group(2)})
    sections: list[dict[str, str]] = []
    for m in _SECTION_RE.finditer(stdout):
        sections.append({"name": m.group(1), "size": m.group(2), "vma": m.group(3)})
    file_format = ""
    m = _FORMAT_RE.search(stdout)
    if m:
        file_format = m.group(1).strip()
    line_count = len(stdout.splitlines())
    instr_count = sum(
        (1 for line in stdout.splitlines() if re.match("^\\s+[0-9a-fA-F]+:", line))
    )
    artifacts: list[Artifact] = []
    if path:
        meta: dict[str, Any] = {}
        if file_format:
            meta["file_format"] = file_format
        if functions:
            meta["function_count"] = len(functions)
        artifacts.append(
            Artifact(path=path, kind="binary", source="objdump", metadata=meta)
        )
    flags = _flag_candidates_from(stdout, source="objdump")
    summary = (
        f"objdump {path}: {len(functions)} function(s), {instr_count} instruction(s)"
    )
    if file_format:
        summary += f" [{file_format}]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "line_count": line_count,
        "function_count": len(functions),
        "instruction_count": instr_count,
    }
    if file_format:
        output_context["file_format"] = file_format
    if functions:
        output_context["functions"] = functions[:30]
    if sections:
        output_context["sections"] = sections[:20]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
