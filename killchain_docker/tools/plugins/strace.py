"""strace — system call tracing for dynamic analysis.

Supports:
  - Tracing syscalls with arguments and return values
  - Structured extraction of file accesses (open/openat paths)
  - Network connection detection (connect/bind/socket)
  - Typed state signals: Artifact, FlagCandidate
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
    ToolOutputStatus,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command

_SYSCALL_RE = re.compile(
    "^(?:\\[\\w+\\]\\s+)?(?:\\d+\\s+)?(\\w+)\\(([^)]*)\\)\\s*=\\s*(.+)$"
)
_EXIT_RE = re.compile("\\+\\+\\+ exited with (\\d+) \\+\\+\\+")
_QUOTED_PATH_RE = re.compile('"([^"]+)"')
_INET_PORT_RE = re.compile("sin_port=htons\\((\\d+)\\)")
_INET_ADDR_RE = re.compile('sin_addr=inet_addr\\("([^"]+)"\\)')
_AF_RE = re.compile("(AF_INET6?|AF_UNIX)")
_FILE_SYSCALLS = frozenset(
    {"open", "openat", "stat", "lstat", "access", "readlink", "execve"}
)
_NET_SYSCALLS = frozenset({"connect", "bind", "sendto", "recvfrom", "socket", "accept"})


class StracePlugin:
    name = "strace"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        args = str(request.metadata.get("args") or "")
        filter_expr = str(request.metadata.get("filter") or "")
        input_data = str(request.metadata.get("input_data") or "")
        files_root = request.metadata.get("files_root")
        cmd_parts = ["strace", "-f", "-s", "200"]
        if filter_expr:
            cmd_parts.extend(["-e", shlex.quote(filter_expr)])
        cmd_parts.append(shlex.quote(path))
        if args:
            cmd_parts.append(args)
        cmd = " ".join(cmd_parts)
        if input_data:
            full_cmd = f"printf %s {shlex.quote(input_data)} | {cmd} 2>&1"
        else:
            full_cmd = f"{cmd} 2>&1"
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
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    combined = stdout + stderr
    status = ToolOutputStatus.SUCCESS
    syscalls: list[dict[str, Any]] = []
    syscall_counts: dict[str, int] = {}
    file_accesses: list[str] = []
    network_connections: list[dict[str, Any]] = []
    exit_status: int | None = None
    seen_files: set[str] = set()
    for line in combined.splitlines():
        line = line.strip()
        m = _EXIT_RE.search(line)
        if m:
            exit_status = int(m.group(1))
            continue
        m = _SYSCALL_RE.match(line)
        if not m:
            continue
        name = m.group(1)
        args_raw = m.group(2)
        ret_val = m.group(3).strip()
        syscall_counts[name] = syscall_counts.get(name, 0) + 1
        entry: dict[str, Any] = {
            "name": name,
            "args": args_raw[:300],
            "return": ret_val[:100],
        }
        syscalls.append(entry)
        if name in _FILE_SYSCALLS:
            for pm in _QUOTED_PATH_RE.finditer(args_raw):
                filepath = pm.group(1)
                if filepath.startswith(("/proc/", "/sys/", "/usr/lib/locale")):
                    continue
                if filepath not in seen_files:
                    seen_files.add(filepath)
                    file_accesses.append(filepath)
        if name in _NET_SYSCALLS:
            af_m = _AF_RE.search(args_raw)
            port_m = _INET_PORT_RE.search(args_raw)
            addr_m = _INET_ADDR_RE.search(args_raw)
            if af_m or port_m or addr_m:
                conn: dict[str, Any] = {}
                if af_m:
                    conn["family"] = af_m.group(1)
                if addr_m:
                    conn["addr"] = addr_m.group(1)
                if port_m:
                    conn["port"] = int(port_m.group(1))
                conn["syscall"] = name
                network_connections.append(conn)
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(
            Artifact(
                path=path,
                kind="binary",
                source="strace",
                metadata={
                    "syscall_count": len(syscalls),
                    "unique_syscalls": len(syscall_counts),
                    "file_access_count": len(file_accesses),
                },
            )
        )
    flags = _flag_candidates_from(combined, source="strace")
    for entry in syscalls:
        if entry["name"] in ("read", "write") and len(entry["args"]) > 50:
            flags.extend(_flag_candidates_from(entry["args"], source="strace:io"))
    summary = f"strace {path}: {len(syscalls)} syscall(s), {len(syscall_counts)} unique"
    if file_accesses:
        summary += f", {len(file_accesses)} file(s) accessed"
    if network_connections:
        summary += f", {len(network_connections)} network connection(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "total_syscalls": len(syscalls),
        "unique_syscalls": len(syscall_counts),
    }
    if syscall_counts:
        sorted_counts = sorted(syscall_counts.items(), key=lambda x: x[1], reverse=True)
        output_context["syscall_summary"] = dict(sorted_counts[:20])
    if file_accesses:
        output_context["file_accesses"] = file_accesses[:30]
    if network_connections:
        output_context["network_connections"] = network_connections[:20]
    if exit_status is not None:
        output_context["exit_status"] = exit_status
    if syscalls:
        relevant = [
            s
            for s in syscalls
            if s["name"] in _FILE_SYSCALLS | _NET_SYSCALLS | {"read", "write", "ioctl"}
        ]
        output_context["relevant_syscalls"] = relevant[:50]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(combined, 4000),
        raw_log=_truncate(combined, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
