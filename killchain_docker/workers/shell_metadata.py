"""shell.exec metadata normalization."""

from __future__ import annotations

from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.run_state import RunState
from killchain_docker.tools.core import ToolExecutionError, _first_string
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.tools.plugins.shell_guard import (
    normalize_shell_stderr_diagnostics,
)


def normalize_shell_metadata(
    raw: dict[str, object], state: RunState
) -> dict[str, object]:
    command = normalize_shell_stderr_diagnostics(_first_string(raw["command"]) or "")
    validate_shell_command(command)
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    scope_reason = scratch_path_reference_block_reason(
        command
    ) or ambient_filesystem_block_reason(
        command, files_root=files_root, authorized_scope=state.authorized_scope
    )
    if scope_reason:
        raise ToolExecutionError(
            f"shell.exec blocked: {scope_reason}; use files_root-bound paths or CTF_TEMP_DIR"
        )
    clean: dict[str, object] = {
        "command": command,
        "files_root": files_root,
        "authorized_scope": list(state.authorized_scope),
    }
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    if "max_workspace_mb" in raw:
        clean["max_workspace_mb"] = raw["max_workspace_mb"]
    return clean


def validate_shell_command(command: str) -> None:
    reason = ToolGuardPolicy.shell_command_block_reason(command)
    if reason:
        raise ToolExecutionError(reason)
