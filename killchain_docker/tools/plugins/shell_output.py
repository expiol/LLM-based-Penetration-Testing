"""Output interpretation for shell.exec."""

from __future__ import annotations

import re

from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import (
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    ToolOutputStatus,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _infrastructure_failure_signal,
    _status,
)
from killchain_docker.tools.plugins.generated_artifacts import (
    artifact_records_from_stdout,
    artifacts_from_records,
)
from killchain_docker.tools.plugins.shell_guard import (
    HTTP_CLIENT_EXECUTABLES,
    iter_simple_command_tokens,
)


MISSING_COMMAND_RE = re.compile(
    r"(?:^|\n)(?:bash|sh|/bin/sh):(?: line \d+:)?\s*([^:\s]+): command not found\b",
    re.IGNORECASE,
)
MASKED_COMMAND_ERROR_RE = re.compile(
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
SHELL_DIAGNOSTIC_PREFIX_RE = (
    r"(?:(?:bash|sh|/bin/sh)(?:: line \d+)?:|[A-Za-z0-9_./+-]+(?:\[[0-9]+\])?:)"
)
STDOUT_MASKED_COMMAND_ERROR_RE = re.compile(
    r"(?im)^(?P<line>" + SHELL_DIAGNOSTIC_PREFIX_RE + r"\s*.{0,240}\b(?:"
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
PATH_RESOLUTION_ERROR_RE = re.compile(
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
STDOUT_PATH_RESOLUTION_ERROR_RE = re.compile(
    r"(?im)^(?P<line>" + SHELL_DIAGNOSTIC_PREFIX_RE + r"\s*.{0,240}\b(?:"
    r"No such file or directory"
    r"|cannot access"
    r"|cannot stat"
    r"|cannot open"
    r"|cannot read"
    r"|Is a directory"
    r"|Not a directory"
    r")\b.{0,240})$"
)
HTTP_STATUS_ERROR_RE = re.compile(
    r"(?im)^HTTP/[\d.]+\s+(?P<status>[45]\d\d)\b(?P<reason>[^\r\n]{0,120})"
)
HTML_STATUS_ERROR_RE = re.compile(
    r"(?is)<(?:title|h1)>\s*(?P<status>[45]\d\d)\b(?P<reason>[^<]{0,120})</(?:title|h1)>"
)
BOUNDED_PIPE_CONSUMER_RE = re.compile(r"(?:^|[|;&]\s*)(?:head|tail)\b")
OPTIONAL_PROBE_RE = re.compile(r"(?:^|[|;&]\s*)(?:grep|rg|awk|sed)\b", re.IGNORECASE)
STRUCTURED_PROBE_OUTPUT_RE = re.compile(
    r"(?im)(?:"
    r"^Symbol table\b|^ELF Header:|^Program Headers:|^Section Headers:|"
    r"^Disassembly of section\b|^\s*[0-9a-f]{6,}:\s|"
    r"GNU_STACK|GNU_RELRO|\.dynsym|\.plt|@GLIBC_|"
    r"DECIMAL\s+HEXADECIMAL|File Type|MIME Type"
    r")"
)
FILE_LISTING_OUTPUT_RE = re.compile(
    r"(?m)^(?:\./|/home/ctfplayer/ctf_files/|[A-Za-z0-9_. -]+/)[^\r\n]*$"
)


def missing_command_name(stdout: str, stderr: str) -> str | None:
    combined = "\n".join(part for part in (stderr, stdout) if part)
    match = MISSING_COMMAND_RE.search(combined)
    if not match:
        return None
    command = match.group(1).strip()
    return command or None


def masked_command_error_detail(
    stdout: str, stderr: str, exit_code: int | None
) -> str | None:
    if exit_code not in (0, None):
        return None
    match = MASKED_COMMAND_ERROR_RE.search(stderr or "")
    if not match:
        match = STDOUT_MASKED_COMMAND_ERROR_RE.search(stdout or "")
    if not match:
        return None
    return match.group("line").strip()[:300]


def path_resolution_error_detail(
    stdout: str, stderr: str, exit_code: int | None
) -> str | None:
    if exit_code in (0, None):
        return None
    match = PATH_RESOLUTION_ERROR_RE.search(stderr or "")
    if not match:
        match = STDOUT_PATH_RESOLUTION_ERROR_RE.search(stdout or "")
    if not match:
        return None
    return match.group("line").strip()[:300]


def files_root_missing_path(path_detail: str, files_root: object) -> str | None:
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


def is_known_challenge_file_path(
    path: str, challenge_files: object, files_root: object
) -> bool:
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


def uses_http_client(command: str) -> bool:
    for tokens in iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable in HTTP_CLIENT_EXECUTABLES:
            return True
    return False


def is_http_status_probe(command: str) -> bool:
    for tokens in iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable == "curl" and curl_writeout_requests_status(tokens):
            return True
        if executable == "wget" and wget_spider_reports_status(tokens):
            return True
    return False


def curl_writeout_requests_status(tokens: list[str]) -> bool:
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


def wget_spider_reports_status(tokens: list[str]) -> bool:
    return any(token == "--spider" for token in tokens[1:])


def http_client_error_detail(command: str, stdout: str, stderr: str) -> str | None:
    if not uses_http_client(command):
        return None
    if is_http_status_probe(command):
        return None
    combined = "\n".join(part for part in (stdout, stderr) if part)
    for pattern in (HTTP_STATUS_ERROR_RE, HTML_STATUS_ERROR_RE):
        match = pattern.search(combined)
        if not match:
            continue
        status = match.group("status").strip()
        reason = " ".join(str(match.group("reason") or "").split())
        return f"HTTP {status}{(' ' + reason) if reason else ''}".strip()
    return None


def bounded_sigpipe_observation(
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
    return BOUNDED_PIPE_CONSUMER_RE.search(command) is not None


def partial_probe_observation(
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> bool:
    if exit_code != 1:
        return False
    if not stdout.strip():
        return False
    if path_resolution_error_detail(stdout, stderr, exit_code):
        return False
    if MASKED_COMMAND_ERROR_RE.search(stderr or ""):
        return False
    if STDOUT_MASKED_COMMAND_ERROR_RE.search(stdout or ""):
        return False
    if not (
        OPTIONAL_PROBE_RE.search(command) or BOUNDED_PIPE_CONSUMER_RE.search(command)
    ):
        return False
    return STRUCTURED_PROBE_OUTPUT_RE.search(stdout) is not None or file_listing_output(
        stdout
    )


def optional_probe_no_match_observation(
    command: str,
    stdout: str,
    stderr: str,
    exit_code: int | None,
) -> bool:
    if exit_code != 1:
        return False
    if not OPTIONAL_PROBE_RE.search(command):
        return False
    if path_resolution_error_detail(stdout, stderr, exit_code):
        return False
    stderr_l = (stderr or "").lower()
    if stderr_l and any(
        marker in stderr_l
        for marker in (
            "error",
            "failed",
            "permission denied",
            "not found",
            "no such file",
            "cannot ",
        )
    ):
        return False
    return True


def file_listing_output(stdout: str) -> bool:
    lines = [line.strip() for line in (stdout or "").splitlines() if line.strip()]
    if not lines:
        return False
    matches = sum(1 for line in lines if FILE_LISTING_OUTPUT_RE.match(line))
    return matches >= 2 or matches == len(lines)


def shell_failure_signal(
    stdout: str,
    stderr: str,
    exit_code: int | None,
    *,
    command: str = "",
    files_root: object = DEFAULT_FILES_ROOT,
    challenge_files: object = None,
    masked_error_detail: str | None = None,
    http_error_detail: str | None = None,
) -> tuple[str, str] | None:
    infrastructure = _infrastructure_failure_signal(stdout, stderr, exit_code)
    if infrastructure is not None:
        return infrastructure

    combined_l = "\n".join(part for part in (stderr, stdout) if part).lower()
    missing_command = missing_command_name(stdout, stderr)
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
        return (
            "package_install_blocked",
            "use installed tools or pivot to another approach",
        )
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
        return (
            "stderr_suppression_blocked",
            "keep stderr visible or redirect stderr to stdout with 2>&1",
        )
    if exit_code == 126 and (
        "outside authorized_scope" in combined_l
        or "outside the challenge scope" in combined_l
        or "outside files_root" in combined_l
        or "stay within authorized_scope" in combined_l
    ):
        return "scope_violation_blocked", "stay within authorized_scope and files_root"
    if "[timeout after" in combined_l or (exit_code == -1 and "timeout" in combined_l):
        return (
            "timeout",
            "shell command exceeded its execution timeout; keep useful stdout and reduce or bound the command",
        )
    if (
        exit_code == 125
        or "workspace budget exceeded" in combined_l
        or "no space left on device" in combined_l
    ):
        return (
            "scratch_space_exhausted",
            "reduce generated workspace data and keep outputs bounded",
        )
    path_detail = path_resolution_error_detail(stdout, stderr, exit_code)
    if path_detail:
        missing_path = files_root_missing_path(path_detail, files_root)
        if missing_path and not is_known_challenge_file_path(
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
    if partial_probe_observation(command, stdout, stderr, exit_code):
        return (
            "partial_probe_miss",
            "shell command produced useful probe output, then a later optional probe returned no matches",
        )
    if optional_probe_no_match_observation(command, stdout, stderr, exit_code):
        return (
            "partial_probe_miss",
            "optional shell search/probe returned no matches",
        )
    return None


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
    bounded_sigpipe = bounded_sigpipe_observation(
        full_command,
        stdout,
        stderr,
        result.exit_code,
        has_artifacts=bool(artifact_records),
    )
    partial_probe = partial_probe_observation(
        full_command,
        stdout,
        stderr,
        result.exit_code,
    )
    optional_probe_no_match = optional_probe_no_match_observation(
        full_command,
        stdout,
        stderr,
        result.exit_code,
    )
    if bounded_sigpipe:
        status = ToolOutputStatus.SUCCESS
    elif partial_probe:
        status = ToolOutputStatus.SUCCESS
    elif optional_probe_no_match:
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
        masked_error_detail = masked_command_error_detail(
            stdout,
            stderr,
            result.exit_code,
        )
        if masked_error_detail:
            status = ToolOutputStatus.FAILURE
            summary = f"shell failed (masked error): {command}"
        else:
            http_error_detail = http_client_error_detail(command, stdout, stderr)
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
    elif partial_probe:
        output_context["result_quality"] = "partial_probe_output"
        output_context["partial_reason"] = (
            "later optional probe returned no matches after useful stdout was captured"
        )
    elif optional_probe_no_match:
        output_context["result_quality"] = "partial_probe_miss"
        output_context["partial_reason"] = (
            "optional shell search/probe returned no matches"
        )
    failure = shell_failure_signal(
        stdout,
        stderr,
        result.exit_code,
        command=full_command,
        files_root=request.metadata.get("files_root") or DEFAULT_FILES_ROOT,
        challenge_files=request.metadata.get("challenge_files"),
        masked_error_detail=masked_error_detail,
        http_error_detail=http_error_detail,
    )
    if failure is not None:
        output_context["failure_kind"], output_context["failure_detail"] = failure

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        artifacts=artifacts,
        flag_candidates=flags,
    )
