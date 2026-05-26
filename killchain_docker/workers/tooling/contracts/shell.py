"""Metadata contracts for shell and script execution."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability

SHELL_TOOL_METADATA_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.SHELL_EXEC: {
        "required": ["command"],
        "optional": ["files_root", "timeout_s", "max_workspace_mb"],
        "notes": (
            "Free-form bash -c. Use installed tools with pipes/redirects. "
            "Do not run package-manager updates/installs or language package installs; "
            "if a tool is missing, record that and pivot. Challenge-file changes are "
            "discarded after execution; scratch growth is capped by max_workspace_mb "
            "(default 512). Use CTF_TEMP_DIR for scratch files and write durable "
            "evidence to stdout. Do not use curl/wget for tcp:// or custom raw "
            "services; use script.exec with stdlib sockets instead. Keep stderr "
            "visible; do not hide tool failures with 2>/dev/null or &>/dev/null."
        ),
    },
    ToolCapability.SCRIPT_EXEC: {
        "required": ["script_code"],
        "optional": ["script_language", "files_root", "timeout_s", "max_workspace_mb"],
        "notes": (
            "Write self-contained bounded source. Default python. Supported: python, bash, "
            "sh, javascript, ruby, perl. Avoid package installation and unbounded loops; "
            "use fast-forward math or capped diagnostics for large counters/search spaces. "
            "Runs in a disposable copy of files_root; use CTF_FILES_ROOT or relative paths "
            "for challenge files and CTF_TEMP_DIR/tempfile for scratch files. Scratch "
            "growth is capped by max_workspace_mb (default 512)."
        ),
    },
}
