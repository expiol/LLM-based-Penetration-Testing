"""Prepare executable tool metadata for worker runtime dispatch."""

from __future__ import annotations

from urllib.parse import urlparse

from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.tooling.metadata.router import normalize_tool_metadata


def prepare_execution_metadata(
    *,
    capability: ToolCapability,
    todo: TodoItem,
    state: RunState,
    selected_metadata: dict[str, object],
    worker_name: str,
) -> dict[str, object]:
    metadata = normalize_tool_metadata(capability, todo, state, selected_metadata)
    if worker_name == "recon-worker":
        return _recon_metadata_defaults(metadata, state)
    return metadata


def _recon_metadata_defaults(
    metadata: dict[str, object], state: RunState
) -> dict[str, object]:
    scope = str(
        metadata.get("scope")
        or (state.authorized_scope[0] if state.authorized_scope else "")
    )
    parsed = urlparse(scope)
    if parsed.scheme in {"http", "https"}:
        metadata.setdefault("base_url", scope)
        metadata.setdefault("hostname", parsed.hostname or "")
    else:
        metadata.setdefault("hostname", parsed.hostname or scope)
    metadata.setdefault("asset_id", str(metadata.get("asset_id") or "seed-asset"))
    return metadata


__all__ = ["prepare_execution_metadata"]
