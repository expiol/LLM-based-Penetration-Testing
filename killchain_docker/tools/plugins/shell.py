"""shell.exec plugin entrypoint."""

from __future__ import annotations

from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    loopback_reference_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from killchain_docker.tools.plugins._base import _run, ToolExecutionError
from killchain_docker.tools.plugins.shell_guard import (
    http_client_non_http_url_block_reason,
    normalize_shell_stderr_diagnostics,
    package_install_block_reason,
    stderr_suppression_block_reason,
    unbounded_extraction_block_reason,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command


class ShellPlugin:
    """Execute an arbitrary shell command via ``bash -c``."""

    name = "shell_exec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        command = normalize_shell_stderr_diagnostics(
            str(request.metadata.get("command") or "").strip()
        )
        if not command:
            raise ToolExecutionError("shell.exec requires metadata.command")
        block_reason = package_install_block_reason(command)
        if block_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stderr=f"{block_reason}; use installed tools or pivot to another approach.",
            )
        extraction_reason = unbounded_extraction_block_reason(command)
        if extraction_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stderr=f"{extraction_reason}; keep extraction bounded before running shell.exec.",
            )
        http_client_reason = http_client_non_http_url_block_reason(command)
        if http_client_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stderr=f"{http_client_reason}.",
            )
        stderr_reason = stderr_suppression_block_reason(command)
        if stderr_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stderr=f"{stderr_reason}.",
            )
        files_root = request.metadata.get("files_root") or DEFAULT_FILES_ROOT
        scope_reason = (
            scratch_path_reference_block_reason(command)
            or loopback_reference_block_reason(
                command,
                request.metadata.get("authorized_scope"),
                require_network_client=True,
            )
            or ambient_filesystem_block_reason(
                command,
                files_root=files_root,
                authorized_scope=request.metadata.get("authorized_scope"),
            )
        )
        if scope_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stderr=f"{scope_reason}; stay within authorized_scope, files_root, and CTF_TEMP_DIR.",
            )
        argv = [
            *self.argv_prefix,
            "bash",
            "-c",
            protected_shell_command(
                command,
                files_root,
                max_workspace_mb=request.metadata.get("max_workspace_mb"),
                max_memory_mb=request.metadata.get("max_memory_mb"),
                max_cpu_s=request.metadata.get("max_cpu_s"),
                publish_generated_artifacts=True,
            ),
        ]
        return _run(self.name, argv, request.timeout_s)
