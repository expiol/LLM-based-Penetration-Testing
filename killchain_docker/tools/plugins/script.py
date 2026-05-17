"""script.exec — write LLM-generated code to a temp file and execute it."""

from __future__ import annotations

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

_SUFFIX_MAP = {
    "python": ".py", "bash": ".sh", "sh": ".sh",
    "javascript": ".js", "node": ".js", "ruby": ".rb", "perl": ".pl",
}
_INTERPRETER_MAP = {
    "python": ["python3"], "bash": ["bash"], "sh": ["sh"],
    "javascript": ["node"], "node": ["node"], "ruby": ["ruby"], "perl": ["perl"],
}


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
        suffix = _SUFFIX_MAP.get(language, ".py")
        interpreter = _INTERPRETER_MAP.get(language, [self.python_executable])
        if language == "python":
            interpreter = [self.python_executable]

        escaped_code = script_code.replace("'", "'\\''")
        files_root = request.metadata.get("files_root") or "/home/ctfplayer/ctf_files"
        shell_cmd = (
            f"_s=$(mktemp /tmp/_script_XXXXXX{suffix}) && "
            f"printf '%s' '{escaped_code}' > \"$_s\" && "
            f"cd {files_root} && "
            f"{' '.join(interpreter)} \"$_s\" ; _rc=$? ; rm -f \"$_s\" ; exit $_rc"
        )
        argv = [*self.argv_prefix, "bash", "-c", shell_cmd]
        return _run(self.name, argv, request.timeout_s)


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

    output_context: dict = {}
    if status.value == "success" and not flags:
        output_context["result_quality"] = "partial_no_candidate"

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
