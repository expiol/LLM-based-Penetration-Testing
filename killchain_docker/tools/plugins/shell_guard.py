"""Pre-execution guard policy for shell.exec."""

from __future__ import annotations

import re
import shlex
from urllib.parse import urlparse


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
HTTP_CLIENT_EXECUTABLES = {"curl", "wget"}
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
        return (
            "remote installer scripts piped to a shell are not permitted in shell.exec"
        )
    return None


def http_client_non_http_url_block_reason(command: str) -> str | None:
    """Return a block reason for shell HTTP clients aimed at raw services."""

    for tokens in iter_simple_command_tokens(command):
        if not tokens:
            continue
        executable = tokens[0].rsplit("/", 1)[-1].lower()
        if executable not in HTTP_CLIENT_EXECUTABLES:
            continue
        for token in tokens[1:]:
            url = shell_url_candidate(token)
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
    """Keep stderr visible while preserving stdout suppression intent."""

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
    """Return a deterministic block reason for wasteful shell extraction patterns."""

    for tokens in iter_simple_command_tokens(command):
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


def shell_url_candidate(token: str) -> str | None:
    token = token.strip()
    option_match = _URL_OPTION_RE.match(token)
    if option_match:
        token = option_match.group(1)
    if _URL_START_RE.match(token):
        return token
    return None


def iter_simple_command_tokens(command: str) -> list[list[str]]:
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
