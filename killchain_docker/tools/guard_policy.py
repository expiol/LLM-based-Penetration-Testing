"""Shared guard policy for tool metadata and worker failure classification."""

from __future__ import annotations

import re

from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.plugins.shell import (
    http_client_non_http_url_block_reason,
    package_install_block_reason,
    stderr_suppression_block_reason,
    unbounded_extraction_block_reason,
)


_SHELL_HEREDOC_RE = re.compile(r"<<\s*['\"]?[A-Za-z0-9_.'-]+['\"]?")
_PYTHON_C_RE = re.compile(r"\bpython(?:3(?:\.\d+)?)?\s+-c\s+", re.IGNORECASE)
_PYTHON_C_CONTROL_FLOW_RE = re.compile(
    r"\b(?:with|if|for|while|try|except|finally|def|class)\b"
)
_SOURCE_BUILD_RE = re.compile(
    r"\b(?:gcc|g\+\+|clang|clang\+\+|cc|make|cmake|rustc|javac|go\s+build)\b"
)
_SOURCE_TEXT_MARKERS = (
    "#include",
    "int main(",
    "def main(",
    "import ",
    "class ",
    "function ",
)


class ToolGuardPolicy:
    """Canonical guard decisions shared by tool and worker Modules."""

    @staticmethod
    def shell_command_block_reason(command: str) -> str | None:
        install_reason = package_install_block_reason(command)
        if install_reason:
            return f"shell.exec blocked: {install_reason}; use installed tools or pivot"
        extraction_reason = unbounded_extraction_block_reason(command)
        if extraction_reason:
            return f"shell.exec blocked: {extraction_reason}; keep extraction bounded"
        http_client_reason = http_client_non_http_url_block_reason(command)
        if http_client_reason:
            return f"shell.exec blocked: {http_client_reason}"
        stderr_reason = stderr_suppression_block_reason(command)
        if stderr_reason:
            return f"shell.exec blocked: {stderr_reason}"
        return _shell_program_block_reason(command)

    @staticmethod
    def metadata_failure_kind(
        message: str,
        capability: ToolCapability | None = None,
    ) -> str:
        lowered = message.lower()
        if "python syntax invalid" in lowered or "syntaxerror" in lowered:
            return "syntax_error"
        if "package installation" in lowered or "package-manager" in lowered:
            return "package_install_blocked"
        if (
            "raw binwalk extraction" in lowered
            or "byte-by-byte extraction" in lowered
            or "unboundedly" in lowered
        ):
            return "unbounded_extraction_blocked"
        if "curl supports only http/https" in lowered or "non-http url" in lowered:
            return "non_http_url_blocked"
        if "scratch files must use ctf_temp_dir" in lowered or "hard-code /tmp" in lowered:
            return "scope_violation_blocked"
        if (
            "outside authorized_scope" in lowered
            or "ambient filesystem" in lowered
            or (
                "blocked:" in lowered
                and any(token in lowered for token in ("/home", "/root", "/etc", "/tmp", "/var", "/opt", "files_root"))
            )
        ):
            return "scope_violation_blocked"
        if "complex python" in lowered or "python -c" in lowered:
            return "shell_python_complexity"
        if "missing required metadata" in lowered:
            cap = capability.value if capability is not None else "tool"
            return f"{cap}_metadata_missing"
        if "unguarded third-party import" in lowered:
            return "missing_tool"
        return "metadata_validation"


def _shell_program_block_reason(command: str) -> str | None:
    lowered = command.lower()
    if _PYTHON_C_RE.search(command) and _PYTHON_C_CONTROL_FLOW_RE.search(command):
        return (
            "shell.exec command embeds complex Python in python -c; "
            "use script.exec with complete script_code instead"
        )
    has_source_text = any(marker in lowered for marker in _SOURCE_TEXT_MARKERS)
    if _SHELL_HEREDOC_RE.search(command) and (
        has_source_text or _SOURCE_BUILD_RE.search(command)
    ):
        return (
            "shell.exec command appears to create or compile multi-line source; "
            "use script.exec with complete script_code instead"
        )
    return None
