"""Shared metadata helpers for worker tool execution."""

from __future__ import annotations

from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import ToolExecutionError, _first_string


def merge_tool_metadata(
    contract: dict[str, object],
    todo_context: dict[str, object],
    selected_metadata: dict[str, object],
) -> dict[str, object]:
    """Merge todo defaults with the current LLM decision as authority."""

    required = set(contract.get("required", []))
    optional = set(contract.get("optional", []))
    raw: dict[str, object] = {
        key: value
        for key, value in todo_context.items()
        if key in optional and key not in required
    }
    raw.update(selected_metadata)
    return raw


def first_challenge_file(raw: dict[str, object]) -> str:
    value = raw.get("challenge_files")
    if isinstance(value, (list, tuple, set)):
        for item in value:
            text = _first_string(item)
            if text:
                return text
    return ""


def normalize_challenge_path(value: object, files_root: str) -> str:
    path = (_first_string(value) or "").strip()
    if not path:
        return path
    if path_shell_fragment(path):
        raise ToolExecutionError(
            "CLI tool path looks like a shell fragment; pass a single path or use shell.exec"
        )
    if path.startswith("/") or "://" in path:
        return path
    if path.startswith("./"):
        path = path[2:]
    return f"{files_root.rstrip('/')}/{path}"


def files_root_from(raw: dict[str, object]) -> str:
    return _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT


def path_shell_fragment(path: str) -> bool:
    return any(
        (
            token in path
            for token in ("\n", "\r", ";", "&&", "||", "|", "`", "$(", ">", "<")
        )
    )


def populated_contract_fields(
    raw: dict[str, object], contract: dict[str, object]
) -> dict[str, object]:
    allowed = set(contract.get("required", [])) | set(contract.get("optional", []))
    clean: dict[str, object] = {}
    files_root = files_root_from(raw)
    for key in allowed:
        if key in raw and raw[key] not in (None, "", [], {}):
            if key == "path":
                clean[key] = normalize_challenge_path(raw[key], files_root)
            else:
                clean[key] = raw[key]
    return clean
