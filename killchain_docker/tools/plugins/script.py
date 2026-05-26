"""script.exec plugin entrypoint."""

from __future__ import annotations

import ast
import re
import shlex
from urllib.parse import urlparse

from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    loopback_reference_block_reason,
    python_ambient_filesystem_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.domain import Credential, ExploitAttempt, Session
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

_AUTH_SUCCESS_RE = re.compile(
    r"\b(?:"
    r"login\s+successful|logged\s+in|authenticated|authentication\s+successful|"
    r"access\s+obtained|access\s+granted|session\s+established"
    r")\b",
    re.IGNORECASE,
)
_AUTH_NEGATIVE_RE = re.compile(
    r"\b(?:"
    r"all\s+login\s+attempts\s+failed|login\s+failed|authentication\s+failed|"
    r"not\s+authenticated|access\s+denied|cannot\s+log\s+in|invalid\s+credentials"
    r")\b",
    re.IGNORECASE,
)
_USERNAME_RE = re.compile(r"^\s*(?:user(?:name)?|login)\s*[:=]\s*(.+?)\s*$", re.I)
_PASSWORD_RE = re.compile(r"^\s*(?:pass(?:word)?)\s*[:=]\s*(.*?)\s*$", re.I)
_TRYING_CREDENTIAL_RE = re.compile(
    r"^\s*(?:\[[^\]]+\]\s*)?trying\s+([^\s:/]+)/(.*?)\s*$", re.I
)
_TARGET_URL_RE = re.compile(
    r"^\s*(?:target|url|login\s+url|base\s+url)\s*[:=]\s*(https?://\S+)\s*$",
    re.IGNORECASE,
)
_AUTH_RUNTIME_LINE_RE = re.compile(
    r"^\s*(?:\[[^\]]*(?:success|info|ok)[^\]]*\]\s*)?"
    r"(?:"
    r"login\s+successful!?|logged\s+in\b|"
    r"successfully\s+authenticated\b|authentication\s+successful\b|"
    r"access\s+(?:obtained|granted)\b|session\s+established\b"
    r")",
    re.IGNORECASE,
)
_CODE_DUMP_RE = re.compile(
    r"<\?php|\b(?:public|private|protected)\s+function\b|"
    r"\bclass\s+\w+|::|\bResponse::|\bSession::",
    re.IGNORECASE,
)


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
    authenticated_access = authenticated_access_from_stdout(request, stdout)
    if flags:
        summary += f" - {len(flags)} flag candidate(s)"
    elif near_misses:
        summary += " - readable near-miss output"
    elif authenticated_access["detected"]:
        summary += " - authenticated access"

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
    if authenticated_access["detected"]:
        output_context["authenticated_access"] = authenticated_access["context"]

    if status.value == "failure":
        failure_text = "\n".join(part for part in (stderr, stdout) if part)
        failure_kind, failure_detail = script_failure_signal(
            failure_text,
            result.exit_code,
        )
        output_context["failure_kind"] = failure_kind
        output_context["failure_detail"] = failure_detail

    if status.value == "success" and not flags:
        if authenticated_access["detected"]:
            output_context["result_quality"] = "authenticated_access"
            output_context.pop("failure_kind", None)
            output_context.pop("failure_detail", None)
        elif near_misses:
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
    credentials = list(authenticated_access["credentials"])
    sessions = list(authenticated_access["sessions"])
    if flags or status.value == "failure" or authenticated_access["detected"]:
        exploit_attempts.append(
            ExploitAttempt(
                technique=f"script:{language}",
                success=bool(flags or authenticated_access["detected"]),
                summary=summary,
                flag_candidate_refs=[candidate.value for candidate in flags],
                metadata={
                    "returncode": result.exit_code,
                    **(
                        {"authenticated_access": authenticated_access["context"]}
                        if authenticated_access["detected"]
                        else {}
                    ),
                },
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
        sessions=sessions,
        credentials=credentials,
    )


def authenticated_access_from_stdout(
    request: ToolExecutionRequest, stdout: str
) -> dict[str, object]:
    """Extract generic successful-authentication state from script diagnostics."""
    if not stdout.strip():
        return {"detected": False, "context": {}, "sessions": [], "credentials": []}
    success_lines = authentication_success_lines(stdout)
    if not success_lines:
        return {"detected": False, "context": {}, "sessions": [], "credentials": []}
    if looks_like_source_auth_message(stdout, success_lines):
        return {"detected": False, "context": {}, "sessions": [], "credentials": []}
    negative_hits = len(_AUTH_NEGATIVE_RE.findall(stdout))
    positive_hits = len(success_lines)
    if negative_hits and negative_hits >= positive_hits:
        return {"detected": False, "context": {}, "sessions": [], "credentials": []}
    username, password = extract_success_credentials(stdout)
    target_url = access_target_url(request, stdout)
    label = access_label(stdout, target_url)
    context = {
        "label": label,
        "target_url": target_url,
        "username": username,
        "success_lines": success_lines,
    }
    if password is not None:
        context["password_observed"] = True
    credentials: list[Credential] = []
    secret_ref = None
    if username:
        secret_ref = f"script-auth:{username}:***"
        credentials.append(
            Credential(
                credential_id=f"script-auth-{stable_text_id(label, username)}",
                username=username,
                secret_ref=secret_ref,
                credential_type="authenticated_access",
                source="script.exec",
                metadata={
                    "target_url": target_url,
                    "access_label": label,
                    "password_observed": password is not None,
                    "empty_password": password == "",
                },
            )
        )
    sessions = [
        Session(
            session_id=f"session-script-auth-{stable_text_id(label, username or 'unknown')}",
            username=username or None,
            session_type="authenticated_access",
            status="active",
            secret_ref=secret_ref,
            metadata={"target_url": target_url, "access_label": label},
        )
    ]
    return {
        "detected": True,
        "context": context,
        "sessions": sessions,
        "credentials": credentials,
    }


def extract_success_credentials(stdout: str) -> tuple[str | None, str | None]:
    username: str | None = None
    password: str | None = None
    last_tried: tuple[str, str] | None = None
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        trying = _TRYING_CREDENTIAL_RE.match(line)
        if trying:
            last_tried = (trying.group(1).strip(), trying.group(2).strip())
        user_match = _USERNAME_RE.match(line)
        if user_match:
            username = user_match.group(1).strip()
        pass_match = _PASSWORD_RE.match(line)
        if pass_match:
            password = pass_match.group(1).strip()
    if username is None and last_tried is not None:
        username = last_tried[0]
        password = last_tried[1]
    return username, password


def access_target_url(request: ToolExecutionRequest, stdout: str = "") -> str:
    for key in (
        "target_url",
        "url",
        "base_url",
        "phpmyadmin_url",
        "login_url",
        "endpoint_url",
    ):
        value = str(request.metadata.get(key) or "").strip()
        if value:
            return value
    scope = request.metadata.get("authorized_scope")
    if isinstance(scope, list):
        for value in scope:
            text = str(value).strip()
            if text:
                return text
    for line in stdout.splitlines():
        match = _TARGET_URL_RE.match(line.strip())
        if match:
            return match.group(1).strip()
    return ""


def access_label(stdout: str, target_url: str) -> str:
    if target_url:
        parsed = urlparse(target_url)
        if parsed.netloc:
            return f"{parsed.netloc}{parsed.path or '/'}"
        return target_url
    for line in stdout.splitlines():
        stripped = line.strip(" :=\t")
        if stripped and not stripped.startswith("["):
            return stripped[:80]
    return "script-authenticated-access"


def authentication_success_lines(stdout: str) -> list[str]:
    lines: list[str] = []
    for line in stdout.splitlines():
        if _AUTH_RUNTIME_LINE_RE.search(line):
            lines.append(line.strip()[:180])
            if len(lines) >= 4:
                break
    return lines


def looks_like_source_auth_message(stdout: str, success_lines: list[str]) -> bool:
    if not _CODE_DUMP_RE.search(stdout):
        return False
    has_dynamic_context = bool(
        _USERNAME_RE.search(stdout)
        or _PASSWORD_RE.search(stdout)
        or _TRYING_CREDENTIAL_RE.search(stdout)
        or re.search(
            r"\b(?:target|logged\s+in|database\s+access|cookie|session\s+id)\s*:",
            stdout,
            re.IGNORECASE,
        )
    )
    if has_dynamic_context:
        return False
    return any(
        (
            "set_flash" in line
            or "redirect" in line.lower()
            or line.rstrip().endswith((";", ");", "');", "\");"))
        )
        for line in success_lines
    )


def stable_text_id(*parts: str) -> str:
    text = "-".join(part for part in parts if part).lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return cleaned[:48] or "unknown"
