"""Catalog of metadata contracts shown to worker tool-selection prompts."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.tooling.contracts.artifacts import (
    ARTIFACT_TOOL_METADATA_CONTRACTS,
)
from killchain_docker.workers.tooling.contracts.binary import (
    BINARY_TOOL_METADATA_CONTRACTS,
)
from killchain_docker.workers.tooling.contracts.recovery import (
    RECOVERY_TOOL_METADATA_CONTRACTS,
)
from killchain_docker.workers.tooling.contracts.shell import SHELL_TOOL_METADATA_CONTRACTS
from killchain_docker.workers.tooling.contracts.web import WEB_TOOL_METADATA_CONTRACTS

TOOL_METADATA_CONTRACT_CATALOG: dict[ToolCapability, dict[str, object]] = {
    **SHELL_TOOL_METADATA_CONTRACTS,
    **WEB_TOOL_METADATA_CONTRACTS,
    **ARTIFACT_TOOL_METADATA_CONTRACTS,
    **BINARY_TOOL_METADATA_CONTRACTS,
    **RECOVERY_TOOL_METADATA_CONTRACTS,
}


def tool_metadata_contract(capability: ToolCapability | str) -> dict[str, object]:
    cap = ToolCapability(capability)
    return TOOL_METADATA_CONTRACT_CATALOG.get(cap, {"required": [], "optional": []})
