"""radare2 — binary analysis and disassembly.

Supports:
  - Arbitrary r2 command pipelines (aaa, afl, pdf, iz, etc.)
  - Rich output parsing: function list, string refs, imports, sections
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

_AFL_RE = re.compile("(0x[0-9a-fA-F]+)\\s+\\d+\\s+\\d+\\s+(.+)")
_IZ_RE = re.compile("string=(.+)")
_INFO_RE = re.compile(
    "^(arch|bits|os|type|class|lang|endian|machine)\\s+(.+)",
    re.MULTILINE | re.IGNORECASE,
)


class RadarePlugin:
    name = "radare2"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        cmds = str(request.metadata.get("commands") or "aaa; afl; pdf @ main")
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"r2 -q -c '{cmds}' {path}"],
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
    for m in _AFL_RE.finditer(stdout):
        functions.append({"address": m.group(1), "name": m.group(2).strip()})
    strings_found: list[str] = []
    for m in _IZ_RE.finditer(stdout):
        s = m.group(1).strip()
        if len(s) >= 4:
            strings_found.append(s)
    binary_info: dict[str, str] = {}
    for m in _INFO_RE.finditer(stdout):
        binary_info[m.group(1).lower()] = m.group(2).strip()
    has_crypto = bool(
        re.search(
            "\\b(aes|des|rsa|sha|md5|xor|cipher|encrypt|decrypt)\\b",
            stdout,
            re.IGNORECASE,
        )
    )
    has_network = bool(
        re.search(
            "\\b(socket|connect|send|recv|bind|listen|accept|http|url)\\b",
            stdout,
            re.IGNORECASE,
        )
    )
    artifacts: list[Artifact] = []
    if path:
        meta: dict[str, Any] = {"commands": cmds[:200]}
        if binary_info:
            meta["binary_info"] = binary_info
        artifacts.append(
            Artifact(path=path, kind="binary", source="radare2", metadata=meta)
        )
    flags = _flag_candidates_from(stdout, source="radare2")
    for s in strings_found:
        flags.extend(_flag_candidates_from(s, source="radare2"))
    parts: list[str] = []
    if functions:
        parts.append(f"{len(functions)} function(s)")
    if strings_found:
        parts.append(f"{len(strings_found)} string(s)")
    if binary_info.get("arch"):
        parts.append(binary_info["arch"])
    detail = ", ".join(parts) if parts else f"'{cmds[:60]}'"
    summary = f"r2 {path}: {detail}"
    if has_crypto:
        summary += " [crypto]"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "commands": cmds,
        "function_count": len(functions),
    }
    if functions:
        output_context["functions"] = functions[:30]
    if strings_found:
        output_context["strings"] = strings_found[:30]
    if binary_info:
        output_context["binary_info"] = binary_info
    if has_crypto:
        output_context["has_crypto_refs"] = True
    if has_network:
        output_context["has_network_refs"] = True
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
