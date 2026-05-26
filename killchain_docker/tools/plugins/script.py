"""script.exec plugin entrypoint."""

from __future__ import annotations

import ast
import shlex

from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    loopback_reference_block_reason,
    python_ambient_filesystem_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.domain import ExploitAttempt
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _err_tail,
    _run,
    _status,
    ToolExecutionError,
)
from killchain_docker.tools.plugins.generated_artifacts import (
    artifact_records_from_stdout,
    artifacts_from_records,
)
from killchain_docker.tools.plugins.script_output import (
    flag_candidates_from_script_stdout,
    readable_near_misses,
    script_failure_signal,
    success_output_failure_kind_is_primary,
    traceback_excerpt,
)
from killchain_docker.tools.plugins.script_runtime import (
    effective_timeout_s,
    python_runtime_guard_wrapper,
    python_scope_scan_text,
    script_uses_network_io,
)
from killchain_docker.tools.plugins.workspace import disposable_script_command


INTERPRETER_MAP = {
    "python": ["python3", "-u"],
    "bash": ["bash"],
    "sh": ["sh"],
    "javascript": ["node"],
    "node": ["node"],
    "ruby": ["ruby"],
    "perl": ["perl"],
}


class ScriptPlugin:
    """Write generated code to an isolated workspace and execute it."""

    name = "script_exec"
    mode = ExecutionMode.LOCAL_COMMAND
    python_executable: str = "python3"

    def __init__(
        self,
        *,
        argv_prefix: list[str] | None = None,
        python_executable: str | None = None,
    ) -> None:
        self.argv_prefix = list(argv_prefix or [])
        if python_executable:
            self.python_executable = python_executable

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        script_code = str(request.metadata.get("script_code") or "").strip()
        if not script_code:
            raise ToolExecutionError("script.exec requires metadata.script_code")
        language = str(request.metadata.get("script_language") or "python").lower()
        interpreter = INTERPRETER_MAP.get(language, [self.python_executable])
        if language == "python":
            interpreter = [self.python_executable, "-u"]

        syntax_error = self._check_syntax(script_code, language)
        if syntax_error:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=1,
                stdout="",
                stderr=syntax_error,
            )

        files_root = request.metadata.get("files_root") or DEFAULT_FILES_ROOT
        scope_reason = scratch_path_reference_block_reason(script_code)
        scope_scan_text = (
            python_scope_scan_text(script_code) if language == "python" else script_code
        )
        if script_uses_network_io(script_code, language):
            scope_reason = scope_reason or loopback_reference_block_reason(
                scope_scan_text,
                request.metadata.get("authorized_scope"),
            )
        if language == "python":
            scope_reason = scope_reason or python_ambient_filesystem_block_reason(
                script_code,
                files_root=files_root,
                authorized_scope=request.metadata.get("authorized_scope"),
            )
        else:
            scope_reason = scope_reason or ambient_filesystem_block_reason(
                script_code,
                files_root=files_root,
                authorized_scope=request.metadata.get("authorized_scope"),
            )
        if scope_reason:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=126,
                stdout="",
                stderr=(
                    "scope_violation_blocked: "
                    f"{scope_reason}; stay within authorized_scope, files_root, and CTF_TEMP_DIR."
                ),
            )

        timeout_s = effective_timeout_s(request.timeout_s, script_code, language)
        shell_cmd = disposable_script_command(
            files_root=files_root,
            interpreter_cmd=shlex.join(interpreter),
            max_workspace_mb=request.metadata.get("max_workspace_mb"),
            max_memory_mb=request.metadata.get("max_memory_mb"),
            max_cpu_s=request.metadata.get("max_cpu_s"),
            guard_source=python_runtime_guard_wrapper(timeout_s)
            if language == "python"
            else None,
        )
        argv = [*self.argv_prefix, "bash", "-c", shell_cmd]
        return _run(self.name, argv, timeout_s, input_text=script_code)

    @staticmethod
    def _check_syntax(code: str, language: str) -> str | None:
        """Return an error message if the script has syntax errors."""
        if language == "python":
            try:
                ast.parse(code)
            except SyntaxError as exc:
                lineno = f" (line {exc.lineno})" if exc.lineno else ""
                return f"SyntaxError{lineno}: {exc.msg}"
        elif language in ("bash", "sh"):
            try:
                result = _run(
                    "script_syntax_check",
                    [language, "-n"],
                    5,
                    input_text=code,
                    max_output_bytes=4000,
                )
                if result.exit_code != 0:
                    return (
                        result.stderr.strip()
                        or f"bash -n failed (exit {result.exit_code})"
                    )
            except ToolExecutionError:
                pass
        return None


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    language = str(request.metadata.get("script_language") or "python")
    status = _status(result)
    stdout, stderr = (result.stdout or "", result.stderr or "")
    artifact_records = artifact_records_from_stdout(stdout)
    summary = f"script ({language})"
    if status.value == "failure":
        summary = f"script failed: {_err_tail(stderr) or f'exit {result.exit_code}'}"

    flags = flag_candidates_from_script_stdout(stdout, source=f"script:{language}")
    near_misses = [] if flags else readable_near_misses(stdout)
    if flags:
        summary += f" - {len(flags)} flag candidate(s)"
    elif near_misses:
        summary += " - readable near-miss output"

    output_context: dict[str, object] = {
        "stdout": _truncate(stdout, 4000),
        "stderr": _truncate(stderr, 1500),
        "returncode": result.exit_code,
        "flag_candidates": [candidate.value for candidate in flags],
    }
    traceback = traceback_excerpt("\n".join(part for part in (stderr, stdout) if part))
    if traceback:
        output_context["traceback"] = traceback

    artifacts = artifacts_from_records(
        artifact_records,
        source="script_exec",
        kind_prefix="script_artifact",
    )
    if artifact_records:
        output_context["generated_artifact_records"] = artifact_records[:40]
        output_context["generated_artifacts_durable"] = True
    if near_misses:
        output_context["near_miss_candidates"] = near_misses

    if status.value == "failure":
        failure_text = "\n".join(part for part in (stderr, stdout) if part)
        failure_kind, failure_detail = script_failure_signal(
            failure_text,
            result.exit_code,
        )
        output_context["failure_kind"] = failure_kind
        output_context["failure_detail"] = failure_detail

    if status.value == "success" and not flags:
        if near_misses:
            output_context["result_quality"] = "near_miss"
        else:
            output_text = "\n".join(part for part in (stderr, stdout) if part)
            failure_kind, failure_detail = script_failure_signal(
                output_text,
                result.exit_code,
            )
            output_context["result_quality"] = "partial_no_candidate"
            if success_output_failure_kind_is_primary(
                failure_kind,
                output_text,
                stdout=stdout,
            ):
                output_context["partial_reason"] = failure_detail
                output_context["failure_kind"] = failure_kind
                output_context["failure_detail"] = failure_detail
            else:
                output_context["partial_reason"] = (
                    "script exited successfully but no flag candidate was recovered"
                )
                output_context["failure_kind"] = "no_candidate"
                output_context["failure_detail"] = output_context["partial_reason"]

    exploit_attempts: list[ExploitAttempt] = []
    if flags or status.value == "failure":
        exploit_attempts.append(
            ExploitAttempt(
                technique=f"script:{language}",
                success=bool(flags),
                summary=summary,
                flag_candidate_refs=[candidate.value for candidate in flags],
                metadata={"returncode": result.exit_code},
            )
        )

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        artifacts=artifacts,
        flag_candidates=flags,
        exploit_attempts=exploit_attempts,
    )
