"""shell.exec — free-form shell execution inside the Docker container."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse

from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    loopback_reference_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    ParsedToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _run,
    _status,
    _flag_candidates_from,
    _truncate,
    _infrastructure_failure_signal,
    ToolExecutionError,
)
from killchain_docker.tools.plugins.generated_artifacts import (
    artifact_records_from_stdout,
    artifacts_from_records,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command


_PACKAGE_MANAGER_RE = re.compile(
    r"(?:^|(?:&&|\|\||[;&|])\s*)(?:sudo\s+)?"
    r"(?:apt(?:-get)?|yum|dnf|apk|pacman|zypper|brew)\s+"
    r"(?:update|upgrade|dist-upgrade|install|add|remove|autoremove)\b",
    re.IGNORECASE,
)
_LANGUAGE_INSTALL_RE = re.compile(
    r"(?:^|(?:&&|\|\||[;&|])\s*)(?:sudo\s+)?(?:"
    r"(?:python(?:3)?\s+-m\s+)?pip(?:3)?\s+install"
    r"|npm\s+(?:install|i|add)"
    r"|yarn\s+(?:install|add)"
    r"|gem\s+install"
    r"|cargo\s+install"
    r"|go\s+install"
    r")\b",
    re.IGNORECASE,
)
_REMOTE_INSTALLER_RE = re.compile(
    r"\b(?:curl|wget)\b[^|]{0,240}\|\s*(?:sudo\s+)?(?:sh|bash)\b",
    re.IGNORECASE,
)
_SHELL_COMMAND_SEPARATOR_RE = re.compile(r"(?:&&|\|\||[;|])")
_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*")
_HTTP_CLIENT_EXECUTABLES = {"curl", "wget"}
_HTTP_CLIENT_ALLOWED_SCHEMES = {"http", "https"}
_URL_START_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_URL_OPTION_RE = re.compile(r"^(?:--url|-U)=(.+)$")
_STDERR_SUPPRESSION_RE = re.compile(
    r"(?P<stdout_null>(?P<stdout_redirect>1?>>?)\s*/dev/null\s+2>\s*&\s*1)"
    r"|(?P<both_streams>&(?P<both_append>>?)>\s*/dev/null)"
    r"|(?P<stderr_null>2>>?\s*/dev/null)"
    r"|(?P<stderr_close>2>\s*&-)",
    re.IGNORECASE,
)
_MISSING_COMMAND_RE = re.compile(
    r"(?:^|\n)(?:bash|sh|/bin/sh):(?: line \d+:)?\s*([^:\s]+): command not found\b",
    re.IGNORECASE,
)
_MASKED_COMMAND_ERROR_RE = re.compile(
    r"(?im)^(?P<line>.{0,240}\b(?:"
    r"No such file or directory"
    r"|cannot access"
    r"|cannot stat"
    r"|cannot open"
    r"|cannot read"
    r"|Permission denied"
    r"|Operation not permitted"
    r"|Input/output error"
    r"|Is a directory"
    r"|Not a directory"
    r"|command not found"
    r"|syntax error near unexpected token"
    r"|invalid option"
    r"|unrecognized option"
    r")\b.{0,240})$"
)
_PATH_RESOLUTION_ERROR_RE = re.compile(
    r"(?im)^(?P<line>.{0,240}\b(?:"
    r"No such file or directory"
    r"|cannot access"
    r"|cannot stat"
    r"|cannot open"
    r"|cannot read"
    r"|Is a directory"
    r"|Not a directory"
    r")\b.{0,240})$"
)
_HTTP_STATUS_ERROR_RE = re.compile(r"(?im)^HTTP/[\d.]+\s+(?P<status>[45]\d\d)\b(?P<reason>[^\r\n]{0,120})")
_HTML_STATUS_ERROR_RE = re.compile(
    r"(?is)<(?:title|h1)>\s*(?P<status>[45]\d\d)\b(?P<reason>[^<]{0,120})</(?:title|h1)>"
)
_BOUNDED_PIPE_CONSUMER_RE = re.compile(r"(?:^|[|;&]\s*)(?:head|tail)\b")


def package_install_block_reason(command: str) -> str | None:
    """Return a deterministic block reason for package-installing shell commands."""

    text = command.strip()
    if not text:
        return None
    if _PACKAGE_MANAGER_RE.search(text):
        return "system package installation/update is not permitted in shell.exec"
    if _LANGUAGE_INSTALL_RE.search(text):
        return "language package installation is not permitted in shell.exec"
    if _REMOTE_INSTALLER_RE.search(text):
        return "remote installer scripts piped to a shell are not permitted in shell.exec"
    return None


def http_client_non_http_url_block_reason(command: str) -> str | None:
    """Return a block reason for shell HTTP clients aimed at raw services."""

    for tokens in _iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable not in _HTTP_CLIENT_EXECUTABLES:
            continue
        for token in tokens[1:]:
            url = _shell_url_candidate(token)
            if not url:
                continue
            scheme = urlparse(url).scheme.lower()
            if scheme and scheme not in _HTTP_CLIENT_ALLOWED_SCHEMES:
                return (
                    f"{executable} in shell.exec used a non-HTTP URL {url}; "
                    "use script.exec with a bounded socket harness for raw TCP/custom services"
                )
    return None


def stderr_suppression_block_reason(command: str) -> str | None:
    """Return a block reason when shell commands discard stderr diagnostics."""

    if normalize_shell_stderr_diagnostics(command) != command:
        return (
            "shell.exec suppressed stderr diagnostics; keep stderr visible or "
            "redirect it to stdout with 2>&1 so failures can be repaired"
        )
    return None


def normalize_shell_stderr_diagnostics(command: str) -> str:
    """Keep stderr visible while preserving stdout suppression intent.

    LLM-selected shell commands often probe optional tools or binary-producing
    commands with ``>/dev/null 2>&1``.  Blocking those commands wastes a cycle;
    silently running them loses the diagnostics needed for repair.  This
    normalizer removes only unquoted stderr-to-null/close redirections.
    """

    if not command:
        return command

    out: list[str] = []
    i = 0
    in_single = False
    in_double = False
    escaped = False
    while i < len(command):
        char = command[i]
        if escaped:
            out.append(char)
            escaped = False
            i += 1
            continue
        if char == "\\" and not in_single:
            out.append(char)
            escaped = True
            i += 1
            continue
        if char == "'" and not in_double:
            in_single = not in_single
            out.append(char)
            i += 1
            continue
        if char == '"' and not in_single:
            in_double = not in_double
            out.append(char)
            i += 1
            continue
        if not in_single and not in_double:
            match = _STDERR_SUPPRESSION_RE.match(command, i)
            if match:
                replacement = _stderr_diagnostic_replacement(match)
                if replacement:
                    out.append(replacement)
                i = match.end()
                continue
        out.append(char)
        i += 1
    return "".join(out)


def _stderr_diagnostic_replacement(match: re.Match[str]) -> str:
    if match.group("stdout_null"):
        return f"{match.group('stdout_redirect')} /dev/null"
    if match.group("both_streams"):
        return f"{'>>' if match.group('both_append') else '>'} /dev/null"
    return ""


def unbounded_extraction_block_reason(command: str) -> str | None:
    """Return a deterministic block reason for shell extraction patterns that waste cycles."""

    for tokens in _iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1]
        if executable == "binwalk" and _binwalk_extract_requested(tokens):
            return (
                "raw binwalk extraction can expand unboundedly; use the binwalk "
                "capability with extract=true/max_extract_mb, or inspect offsets and "
                "extract only bounded byte ranges"
            )
        if executable == "dd" and _dd_byte_skip_without_count(tokens):
            return (
                "dd byte-by-byte extraction with skip and no count is unbounded/slow; "
                "add count=..., use a larger block size, or use Python seek/read bounded "
                "by an archive EOF/EOCD"
            )
    return None


def _shell_url_candidate(token: str) -> str | None:
    token = token.strip()
    option_match = _URL_OPTION_RE.match(token)
    if option_match:
        token = option_match.group(1)
    if _URL_START_RE.match(token):
        return token
    return None


def _iter_simple_command_tokens(command: str) -> list[list[str]]:
    commands: list[list[str]] = []
    for segment in _SHELL_COMMAND_SEPARATOR_RE.split(command):
        text = segment.strip()
        if not text:
            continue
        try:
            tokens = shlex.split(text)
        except ValueError:
            tokens = text.split()
        commands.append(_strip_command_prefixes(tokens))
    return commands


def _strip_command_prefixes(tokens: list[str]) -> list[str]:
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token in {"sudo", "command", "builtin"}:
            i += 1
            continue
        if token == "env":
            i += 1
            continue
        if _ASSIGNMENT_RE.fullmatch(token):
            i += 1
            continue
        if token == "timeout":
            i += 1
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1
            if i < len(tokens):
                i += 1
            continue
        break
    return tokens[i:]


def _binwalk_extract_requested(tokens: list[str]) -> bool:
    for token in tokens[1:]:
        if token == "--":
            return False
        if token == "--extract" or token.startswith("--extract="):
            return True
        if token.startswith("--"):
            continue
        if token.startswith("-") and "e" in token[1:]:
            return True
    return False


def _dd_byte_skip_without_count(tokens: list[str]) -> bool:
    args: dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        args[key.lower()] = value
    return (
        args.get("bs", "").lower() in {"1", "1c"}
        and "skip" in args
        and "count" not in args
    )


def _missing_command_name(stdout: str, stderr: str) -> str | None:
    combined = "\n".join(part for part in (stderr, stdout) if part)
    match = _MISSING_COMMAND_RE.search(combined)
    if not match:
        return None
    command = match.group(1).strip()
    return command or None


def _masked_command_error_detail(stdout: str, stderr: str, exit_code: int | None) -> str | None:
    if exit_code not in (0, None):
        return None
    combined = "\n".join(part for part in (stderr, stdout) if part)
    match = _MASKED_COMMAND_ERROR_RE.search(combined)
    if not match:
        return None
    return match.group("line").strip()[:300]


def _path_resolution_error_detail(stdout: str, stderr: str, exit_code: int | None) -> str | None:
    if exit_code in (0, None):
        return None
    combined = "\n".join(part for part in (stderr, stdout) if part)
    match = _PATH_RESOLUTION_ERROR_RE.search(combined)
    if not match:
        return None
    return match.group("line").strip()[:300]


def _files_root_missing_path(path_detail: str, files_root: object) -> str | None:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    if not root:
        return None
    pattern = re.compile(re.escape(root) + r"/[^\s'\"`<>|&;]+")
    match = pattern.search(path_detail)
    if not match:
        return None
    path = match.group(0).rstrip(".,:)]}")
    if path == root or path.startswith(root + "/.autopentest_artifacts/"):
        return None
    return path


def _is_known_challenge_file_path(path: str, challenge_files: object, files_root: object) -> bool:
    if not isinstance(challenge_files, (list, tuple, set, frozenset)):
        return False
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    if not root or not path.startswith(root + "/"):
        return False
    rel = path[len(root) + 1 :].strip("/")
    basename = rel.rsplit("/", 1)[-1]
    for raw in challenge_files:
        candidate = str(raw or "").strip().strip("/")
        if candidate and (candidate == rel or candidate.rsplit("/", 1)[-1] == basename):
            return True
    return False


def _uses_http_client(command: str) -> bool:
    for tokens in _iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable in _HTTP_CLIENT_EXECUTABLES:
            return True
    return False


def _is_http_status_probe(command: str) -> bool:
    for tokens in _iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable == "curl" and _curl_writeout_requests_status(tokens):
            return True
        if executable == "wget" and _wget_spider_reports_status(tokens):
            return True
    return False


def _curl_writeout_requests_status(tokens: list[str]) -> bool:
    status_fields = ("%{http_code}", "%{response_code}", "%{http_connect}")
    idx = 1
    while idx < len(tokens):
        token = tokens[idx]
        value = ""
        if token in {"-w", "--write-out"} and idx + 1 < len(tokens):
            value = tokens[idx + 1]
            idx += 2
        elif token.startswith("--write-out="):
            value = token.split("=", 1)[1]
            idx += 1
        elif token.startswith("-w") and len(token) > 2:
            value = token[2:]
            idx += 1
        else:
            idx += 1
        if value and any(field in value for field in status_fields):
            return True
    return False


def _wget_spider_reports_status(tokens: list[str]) -> bool:
    return any(token == "--spider" for token in tokens[1:])


def _http_client_error_detail(command: str, stdout: str, stderr: str) -> str | None:
    if not _uses_http_client(command):
        return None
    if _is_http_status_probe(command):
        return None
    combined = "\n".join(part for part in (stdout, stderr) if part)
    for pattern in (_HTTP_STATUS_ERROR_RE, _HTML_STATUS_ERROR_RE):
        match = pattern.search(combined)
        if not match:
            continue
        status = match.group("status").strip()
        reason = " ".join(str(match.group("reason") or "").split())
        return f"HTTP {status}{(' ' + reason) if reason else ''}".strip()
    return None


def _bounded_sigpipe_observation(
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
    *,
    has_artifacts: bool,
) -> bool:
    if exit_code != 141:
        return False
    if not stdout.strip() and not has_artifacts:
        return False
    if "error" in stderr.lower() and "broken pipe" not in stderr.lower():
        return False
    return _BOUNDED_PIPE_CONSUMER_RE.search(command) is not None


def _shell_failure_signal(
    stdout: str,
    stderr: str,
    exit_code: int | None,
    *,
    files_root: object = DEFAULT_FILES_ROOT,
    challenge_files: object = None,
    masked_error_detail: str | None = None,
    http_error_detail: str | None = None,
) -> tuple[str, str] | None:
    infrastructure = _infrastructure_failure_signal(stdout, stderr, exit_code)
    if infrastructure is not None:
        return infrastructure

    combined_l = "\n".join(part for part in (stderr, stdout) if part).lower()
    missing_command = _missing_command_name(stdout, stderr)
    if exit_code == 127 and missing_command:
        return (
            "missing_tool",
            f"required shell command not found: {missing_command}; "
            "check command availability and pivot to installed tools or script.exec",
        )
    if masked_error_detail:
        return (
            "masked_shell_error",
            "shell command emitted a fatal diagnostic even though the final "
            f"pipeline exit code was 0: {masked_error_detail}",
        )
    if http_error_detail:
        return (
            "http_error_response",
            "shell HTTP client returned an HTTP error response: "
            f"{http_error_detail}; retry the correct route, method, redirects, or session handling",
        )
    if exit_code == 126 and (
        "package installation" in combined_l
        or "installer scripts" in combined_l
        or "not permitted in shell.exec" in combined_l
    ):
        return "package_install_blocked", "use installed tools or pivot to another approach"
    if exit_code == 126 and (
        "raw binwalk extraction" in combined_l
        or "byte-by-byte extraction" in combined_l
        or "unboundedly" in combined_l
    ):
        return (
            "unbounded_extraction_blocked",
            "use bounded extraction, dedicated binwalk metadata, or Python seek/read",
        )
    if exit_code == 126 and "non-http url" in combined_l:
        return (
            "non_http_url_blocked",
            "use script.exec with bounded socket timeouts for raw TCP/custom services",
        )
    if exit_code == 126 and "suppressed stderr diagnostics" in combined_l:
        return "stderr_suppression_blocked", "keep stderr visible or redirect stderr to stdout with 2>&1"
    if exit_code == 126 and (
        "outside authorized_scope" in combined_l
        or "outside the challenge scope" in combined_l
        or "outside files_root" in combined_l
        or "stay within authorized_scope" in combined_l
    ):
        return "scope_violation_blocked", "stay within authorized_scope and files_root"
    if "[timeout after" in combined_l or (
        exit_code == -1 and "timeout" in combined_l
    ):
        return (
            "timeout",
            "shell command exceeded its execution timeout; keep useful stdout and reduce or bound the command",
        )
    if (
        exit_code == 125
        or "workspace budget exceeded" in combined_l
        or "no space left on device" in combined_l
    ):
        return "scratch_space_exhausted", "reduce generated workspace data and keep outputs bounded"
    path_detail = _path_resolution_error_detail(stdout, stderr, exit_code)
    if path_detail:
        missing_path = _files_root_missing_path(path_detail, files_root)
        if missing_path and not _is_known_challenge_file_path(
            missing_path,
            challenge_files,
            files_root,
        ):
            return (
                "non_durable_workspace_path",
                "shell.exec restores the files_root workspace after each call; "
                "paths produced by prior tool calls are not durable at their "
                f"original location ({missing_path}). Use registered durable "
                "generated artifact paths under .autopentest_artifacts, or "
                "create and read the path within the same tool call.",
            )
        return (
            "path_resolution_error",
            "shell command referenced a path that was not present in the execution workspace: "
            f"{path_detail}",
        )
    return None


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
            or
            loopback_reference_block_reason(
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


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    full_command = str(request.metadata.get("command") or "")
    command = full_command[:200]
    status = _status(result)
    stdout, stderr = result.stdout or "", result.stderr or ""
    artifact_records = artifact_records_from_stdout(stdout)
    bounded_sigpipe = _bounded_sigpipe_observation(
        full_command,
        stdout,
        stderr,
        result.exit_code,
        has_artifacts=bool(artifact_records),
    )
    if bounded_sigpipe:
        status = ToolOutputStatus.SUCCESS

    summary = f"shell: {command}"
    if status.value == "failure":
        summary = f"shell failed (exit {result.exit_code}): {command}"

    flags = _flag_candidates_from(stdout, source=f"shell:{command[:80]}")
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    elif artifact_records:
        summary += f" — {len(artifact_records)} generated artifact(s)"
    masked_error_detail = None
    http_error_detail = None
    if status == ToolOutputStatus.SUCCESS and not flags:
        masked_error_detail = _masked_command_error_detail(
            stdout,
            stderr,
            result.exit_code,
        )
        if masked_error_detail:
            status = ToolOutputStatus.FAILURE
            summary = f"shell failed (masked error): {command}"
        else:
            http_error_detail = _http_client_error_detail(command, stdout, stderr)
            if http_error_detail:
                status = ToolOutputStatus.FAILURE
                summary = f"shell failed (http error response): {command}"

    output_context: dict = {
        "stdout": _truncate(stdout, 4000),
        "stderr": _truncate(stderr, 1500),
        "returncode": result.exit_code,
        "flag_candidates": [fc.value for fc in flags],
        "workspace_restored": True,
    }
    artifacts = artifacts_from_records(
        artifact_records,
        source="shell_exec",
        kind_prefix="shell_artifact",
    )
    if artifact_records:
        output_context["generated_artifact_records"] = artifact_records[:40]
        output_context["generated_artifacts_durable"] = True
    if bounded_sigpipe:
        output_context["result_quality"] = "bounded_pipe_closed"
        output_context["partial_reason"] = (
            "bounded pipeline consumer closed after useful output was captured"
        )
    failure = _shell_failure_signal(
        stdout,
        stderr,
        result.exit_code,
        files_root=request.metadata.get("files_root") or DEFAULT_FILES_ROOT,
        challenge_files=request.metadata.get("challenge_files"),
        masked_error_detail=masked_error_detail,
        http_error_detail=http_error_detail,
    )
    if failure is not None:
        output_context["failure_kind"], output_context["failure_detail"] = failure

    return ToolOutput(
        status=status, summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        artifacts=artifacts,
        flag_candidates=flags,
    )
