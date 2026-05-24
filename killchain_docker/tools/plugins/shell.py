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
    r"(?:^|[\s;|&])(?:2>>?\s*/dev/null|2>\s*&-|&>>?\s*/dev/null)"
    r"|>\s*/dev/null\s+2>&1",
    re.IGNORECASE,
)
_MISSING_COMMAND_RE = re.compile(
    r"(?:^|\n)(?:bash|sh|/bin/sh):(?: line \d+:)?\s*([^:\s]+): command not found\b",
    re.IGNORECASE,
)


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

    if _STDERR_SUPPRESSION_RE.search(command):
        return (
            "shell.exec suppressed stderr diagnostics; keep stderr visible or "
            "redirect it to stdout with 2>&1 so failures can be repaired"
        )
    return None


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


class ShellPlugin:
    """Execute an arbitrary shell command via ``bash -c``."""

    name = "shell_exec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        command = str(request.metadata.get("command") or "").strip()
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
            ),
        ]
        return _run(self.name, argv, request.timeout_s)


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    command = str(request.metadata.get("command") or "")[:200]
    status = _status(result)
    stdout, stderr = result.stdout or "", result.stderr or ""

    summary = f"shell: {command}"
    if status.value == "failure":
        summary = f"shell failed (exit {result.exit_code}): {command}"

    flags = _flag_candidates_from(stdout, source=f"shell:{command[:80]}")
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    output_context: dict = {
        "stdout": _truncate(stdout, 4000),
        "stderr": _truncate(stderr, 1500),
        "returncode": result.exit_code,
        "flag_candidates": [fc.value for fc in flags],
    }
    stderr_l = stderr.lower()
    infrastructure = _infrastructure_failure_signal(stdout, stderr, result.exit_code)
    if infrastructure is not None:
        output_context["failure_kind"], output_context["failure_detail"] = infrastructure
        return ToolOutput(
            status=status, summary=summary,
            output_text=_truncate(stdout, 4000),
            raw_log=_truncate(stdout + stderr, 6000),
            output_context=output_context,
            flag_candidates=flags,
        )
    missing_command = _missing_command_name(stdout, stderr)
    if result.exit_code == 127 and missing_command:
        output_context["failure_kind"] = "missing_tool"
        output_context["failure_detail"] = (
            f"required shell command not found: {missing_command}; "
            "check command availability and pivot to installed tools or script.exec"
        )
    if result.exit_code == 126 and (
        "package installation" in stderr_l
        or "installer scripts" in stderr_l
        or "not permitted in shell.exec" in stderr_l
    ):
        output_context["failure_kind"] = "package_install_blocked"
        output_context["failure_detail"] = "use installed tools or pivot to another approach"
    if result.exit_code == 126 and (
        "raw binwalk extraction" in stderr_l
        or "byte-by-byte extraction" in stderr_l
        or "unboundedly" in stderr_l
    ):
        output_context["failure_kind"] = "unbounded_extraction_blocked"
        output_context["failure_detail"] = (
            "use bounded extraction, dedicated binwalk metadata, or Python seek/read"
        )
    if result.exit_code == 126 and "non-http url" in stderr_l:
        output_context["failure_kind"] = "non_http_url_blocked"
        output_context["failure_detail"] = (
            "use script.exec with bounded socket timeouts for raw TCP/custom services"
        )
    if result.exit_code == 126 and "suppressed stderr diagnostics" in stderr_l:
        output_context["failure_kind"] = "stderr_suppression_blocked"
        output_context["failure_detail"] = (
            "keep stderr visible or redirect stderr to stdout with 2>&1"
        )
    if result.exit_code == 126 and (
        "outside authorized_scope" in stderr_l
        or "outside the challenge scope" in stderr_l
        or "outside files_root" in stderr_l
        or "stay within authorized_scope" in stderr_l
    ):
        output_context["failure_kind"] = "scope_violation_blocked"
        output_context["failure_detail"] = "stay within authorized_scope and files_root"
    if "workspace budget exceeded" in stderr_l or "no space left on device" in stderr_l:
        output_context["failure_kind"] = "scratch_space_exhausted"
        output_context["failure_detail"] = "reduce generated scratch data and keep outputs bounded"

    return ToolOutput(
        status=status, summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
    )
