"""Capability enum, tool specs, and gateway.

Each ToolCapability maps 1:1 to a registered plugin.
"""

from __future__ import annotations

from dataclasses import dataclass
from killchain_docker._compat import StrEnum
from typing import Any

from killchain_docker.tools.core import (
    ExecutionPlane,
    ToolExecutionBundle,
    ToolExecutionRequest,
)


class ToolCapability(StrEnum):
    # Universal low-level
    SHELL_EXEC = "shell.exec"
    SCRIPT_EXEC = "script.exec"

    # Network recon
    NMAP = "nmap"
    CURL = "curl"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"

    # Binary / file analysis
    FILE_CMD = "file_cmd"
    STRINGS_CMD = "strings_cmd"
    BINWALK = "binwalk"
    RADARE2 = "radare2"
    OBJDUMP = "objdump"
    GDB = "gdb"

    # Forensics / stego
    TSHARK = "tshark"
    EXIFTOOL = "exiftool"
    STEGHIDE = "steghide"
    FOREMOST = "foremost"

    # Database
    SQLITE3 = "sqlite3"

    # Crypto / cracking
    JOHN = "john"
    FCRACKZIP = "fcrackzip"

    # APK / Java
    JADX = "jadx"


@dataclass(frozen=True)
class ToolSpec:
    """Concrete plugin binding for one capability."""

    capability: ToolCapability
    tool_name: str
    default_timeout_s: int = 120


# Auto-generate specs: capability value == plugin name for all CLI tools.
# Shell and script have separate plugin names.
DEFAULT_TOOL_SPECS: dict[ToolCapability, ToolSpec] = {
    ToolCapability.SHELL_EXEC: ToolSpec(ToolCapability.SHELL_EXEC, "shell_exec"),
    ToolCapability.SCRIPT_EXEC: ToolSpec(ToolCapability.SCRIPT_EXEC, "script_exec"),
}
for _cap in ToolCapability:
    if _cap not in DEFAULT_TOOL_SPECS:
        DEFAULT_TOOL_SPECS[_cap] = ToolSpec(_cap, _cap.value)


class ToolGateway:
    """Route capability requests to the execution plane."""

    def __init__(
        self,
        execution_plane: ExecutionPlane,
        *,
        specs: dict[ToolCapability, ToolSpec] | None = None,
    ) -> None:
        self.execution_plane = execution_plane
        self.specs = dict(specs or DEFAULT_TOOL_SPECS)

    def run(
        self,
        *,
        task_id: str,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle:
        cap = ToolCapability(capability)
        spec = self.specs[cap]
        request = ToolExecutionRequest(
            capability=cap.value,
            tool_name=spec.tool_name,
            timeout_s=timeout_s or spec.default_timeout_s,
            metadata=metadata,
        )
        return self.execution_plane.execute(task_id, request)
