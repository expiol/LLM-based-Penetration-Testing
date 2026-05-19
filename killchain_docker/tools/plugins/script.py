"""script.exec — write LLM-generated code to a temp file and execute it."""

from __future__ import annotations

import ast
import shlex

from killchain_docker.state import ExploitAttempt
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
    _err_tail,
    ToolExecutionError,
)

_INTERPRETER_MAP = {
    "python": ["python3", "-u"], "bash": ["bash"], "sh": ["sh"],
    "javascript": ["node"], "node": ["node"], "ruby": ["ruby"], "perl": ["perl"],
}


def _script_failure_signal(stderr: str, exit_code: int | None) -> tuple[str, str]:
    text = stderr.lower()
    if "brokenpipeerror" in text:
        return "network_pipe_closed", "remote endpoint closed the socket while the script was writing"
    if "connectionreseterror" in text or "connection reset by peer" in text:
        return "connection_reset", "remote endpoint reset the connection"
    if "connectionrefusederror" in text or "connection refused" in text:
        return "connection_refused", "remote endpoint refused the connection"
    if "timed out" in text or "timeouterror" in text or "[timeout after" in text:
        return "timeout", "script exceeded its execution or socket timeout"
    if (
        "a bytes-like object is required" in text
        or "can't concat str to bytes" in text
        or "can't concat bytes to str" in text
        or "must be str, not bytes" in text
        or "must be bytes, not str" in text
    ):
        return "bytes_text_mismatch", "script mixed bytes and text across an IO boundary"
    if "syntaxerror" in text:
        return "syntax_error", "script failed Python or shell syntax validation"
    return "nonzero_exit", f"script exited with status {exit_code}"


class ScriptPlugin:
    """Write LLM-generated code to a temp file and execute it."""

    name = "script_exec"
    mode = ExecutionMode.LOCAL_COMMAND
    python_executable: str = "python3"

    def __init__(self, *, argv_prefix: list[str] | None = None, python_executable: str | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])
        if python_executable:
            self.python_executable = python_executable

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        script_code = str(request.metadata.get("script_code") or "").strip()
        if not script_code:
            raise ToolExecutionError("script.exec requires metadata.script_code")

        language = str(request.metadata.get("script_language") or "python").lower()
        interpreter = _INTERPRETER_MAP.get(language, [self.python_executable])
        if language == "python":
            interpreter = [self.python_executable, "-u"]

        # Syntax check before execution — fail fast without wasting container time
        syntax_error = self._check_syntax(script_code, language)
        if syntax_error:
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=1,
                stdout="",
                stderr=syntax_error,
            )

        files_root = request.metadata.get("files_root") or "/home/ctfplayer/ctf_files"
        interpreter_cmd = shlex.join(interpreter)
        shell_cmd = (
            "_s=$(mktemp /tmp/_script_XXXXXX) && "
            f"cat > \"$_s\" && "
            f"cd {shlex.quote(str(files_root))} && "
            f"{interpreter_cmd} \"$_s\" ; _rc=$? ; rm -f \"$_s\" ; exit $_rc"
        )
        argv = [*self.argv_prefix, "bash", "-c", shell_cmd]
        return _run(self.name, argv, request.timeout_s, input_text=script_code)

    @staticmethod
    def _check_syntax(code: str, language: str) -> str | None:
        """Return an error message if the script has syntax errors, else None."""
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
                    return result.stderr.strip() or f"bash -n failed (exit {result.exit_code})"
            except ToolExecutionError:
                pass  # Cannot check locally — let it run in container
        return None


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    language = str(request.metadata.get("script_language") or "python")
    status = _status(result)
    stdout, stderr = result.stdout or "", result.stderr or ""

    summary = f"script ({language})"
    if status.value == "failure":
        summary = f"script failed: {_err_tail(stderr) or f'exit {result.exit_code}'}"

    flags = _flag_candidates_from(stdout, source=f"script:{language}")
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    output_context: dict = {
        "stdout": _truncate(stdout, 4000),
        "stderr": _truncate(stderr, 1500),
        "returncode": result.exit_code,
        "flag_candidates": [fc.value for fc in flags],
    }
    if status.value == "failure":
        failure_kind, failure_detail = _script_failure_signal(stderr, result.exit_code)
        output_context["failure_kind"] = failure_kind
        output_context["failure_detail"] = failure_detail
    if status.value == "success" and not flags:
        output_context["result_quality"] = "partial_no_candidate"
        output_context["partial_reason"] = "script exited successfully but no flag candidate was recovered"
        output_context["failure_kind"] = "no_candidate"
        output_context["failure_detail"] = output_context["partial_reason"]

    exploit_attempts: list[ExploitAttempt] = []
    if flags or status.value == "failure":
        exploit_attempts.append(ExploitAttempt(
            technique=f"script:{language}", success=bool(flags),
            summary=summary,
            flag_candidate_refs=[fc.value for fc in flags],
            metadata={"returncode": result.exit_code},
        ))

    return ToolOutput(
        status=status, summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        exploit_attempts=exploit_attempts,
    )
