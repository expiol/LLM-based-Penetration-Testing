"""Route capability metadata to specific normalizers."""

from __future__ import annotations

from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionError, _first_string
from killchain_docker.workers.artifact_metadata import (
    normalize_artifact_triage_metadata,
    normalize_disk_extract_metadata,
    normalize_media_scan_metadata,
    normalize_office_inspect_metadata,
    normalize_png_inspect_metadata,
)
from killchain_docker.workers.http_metadata import normalize_curl_metadata
from killchain_docker.workers.metadata_common import (
    merge_tool_metadata,
    populated_contract_fields,
)
from killchain_docker.workers.script_metadata import normalize_script_metadata
from killchain_docker.workers.shell_metadata import normalize_shell_metadata
from killchain_docker.workers.tool_contract_catalog import (
    TOOL_METADATA_CONTRACT_CATALOG,
)


def normalize_tool_metadata(
    capability: ToolCapability | str,
    todo: TodoItem,
    state: RunState,
    selected_metadata: dict[str, object],
) -> dict[str, object]:
    """Validate and clean metadata before dispatching to a plugin."""
    cap = ToolCapability(capability)
    contract = TOOL_METADATA_CONTRACT_CATALOG.get(cap)
    if not contract:
        raise ToolExecutionError(f"Unknown capability: {cap.value}")
    raw = merge_tool_metadata(contract, todo.context, selected_metadata)
    for field in contract.get("required", []):
        if not _first_string(raw.get(field)):
            raise ToolExecutionError(f"{cap.value} missing required metadata.{field}")
    if cap == ToolCapability.SHELL_EXEC:
        return normalize_shell_metadata(raw, state)
    if cap == ToolCapability.SCRIPT_EXEC:
        return normalize_script_metadata(raw, state)
    if cap == ToolCapability.CURL:
        return normalize_curl_metadata(raw, contract)
    if cap == ToolCapability.ARTIFACT_TRIAGE:
        return normalize_artifact_triage_metadata(raw)
    if cap == ToolCapability.DISK_EXTRACT:
        return normalize_disk_extract_metadata(raw)
    if cap == ToolCapability.OFFICE_INSPECT:
        return normalize_office_inspect_metadata(raw)
    if cap == ToolCapability.MEDIA_SCAN:
        return normalize_media_scan_metadata(raw)
    if cap == ToolCapability.PNG_INSPECT:
        return normalize_png_inspect_metadata(raw)
    if "path" in contract.get("required", []):
        raw["files_root"] = (
            _first_string(raw.get("files_root"))
            or _first_string(todo.context.get("files_root"))
            or DEFAULT_FILES_ROOT
        )
    return populated_contract_fields(raw, contract)
