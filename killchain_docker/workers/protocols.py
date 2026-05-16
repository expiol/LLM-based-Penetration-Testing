"""Persona protocol and worker architecture.

A Persona defines the strategy for a worker: which capabilities it can use,
how it prepares metadata, and any custom post-processing. The Worker class
provides the shared execution loop; persona differences are data + strategy,
not separate class hierarchies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from killchain_docker.tools.capabilities import ToolCapability


class Persona(Protocol):
    """Strategy object injected into Worker to define persona behavior."""

    @property
    def name(self) -> str: ...

    @property
    def allowed_capabilities(self) -> tuple[ToolCapability, ...]: ...

    @property
    def routing_summary(self) -> str: ...

    @property
    def supported_todo_kinds(self) -> tuple[str, ...]: ...

    @property
    def preferred_challenge_categories(self) -> tuple[str, ...]: ...

    @property
    def required_context_keys(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class PersonaSpec:
    """Concrete persona specification — data, not code."""

    name: str
    allowed_capabilities: tuple[ToolCapability, ...]
    routing_summary: str = ""
    supported_todo_kinds: tuple[str, ...] = ("todo",)
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Predefined persona specs matching the original 5 worker classes
# ---------------------------------------------------------------------------

RECON_PERSONA = PersonaSpec(
    name="recon-worker",
    routing_summary="Maps authorized scope into assets and collects first-pass host or HTTP metadata.",
    allowed_capabilities=(
        ToolCapability.HTTP_METADATA,
        ToolCapability.HOST_INVENTORY,
        ToolCapability.HOST_BANNER,
    ),
)

ARTIFACT_PERSONA = PersonaSpec(
    name="artifact-worker",
    routing_summary="Inspects bundled files, source, binaries, archives, repositories, databases, and packet captures.",
    preferred_challenge_categories=("crypto", "rev", "forensics", "misc", "pwn", "web"),
    allowed_capabilities=(
        ToolCapability.ARTIFACT_TRIAGE,
        ToolCapability.ARTIFACT_SOURCE,
        ToolCapability.ARTIFACT_BINARY_TRIAGE,
        ToolCapability.ARTIFACT_BINARY_DISASSEMBLE,
        ToolCapability.ARTIFACT_BINARY_EXECUTE,
        ToolCapability.ARTIFACT_ARCHIVE,
        ToolCapability.ARTIFACT_SQLITE,
        ToolCapability.ARTIFACT_PCAP,
        ToolCapability.ARTIFACT_REPO,
        ToolCapability.ARTIFACT_RUNTIME,
        ToolCapability.ARTIFACT_COMPUTATION,
        ToolCapability.SCRIPT_EXECUTE,
        ToolCapability.FLAG_HARVEST,
    ),
)

WEB_PERSONA = PersonaSpec(
    name="web-worker",
    routing_summary="Reviews HTTP content, probes routes, and interacts with discovered forms inside authorized scope.",
    preferred_challenge_categories=("web",),
    allowed_capabilities=(
        ToolCapability.HTTP_METADATA,
        ToolCapability.HTTP_CONTENT,
        ToolCapability.HTTP_PROBE_PATHS,
        ToolCapability.HTTP_FORM_PROBE,
        ToolCapability.CREDENTIAL_LOGIN,
        ToolCapability.SCRIPT_EXECUTE,
    ),
)

EXPLOIT_PERSONA = PersonaSpec(
    name="exploit-worker",
    routing_summary="Runs bounded exploit, credential, vulnerability, and script experiments from accumulated evidence.",
    allowed_capabilities=(
        ToolCapability.VULN_SCAN,
        ToolCapability.EXPLOIT_PROBE,
        ToolCapability.CREDENTIAL_LOGIN,
        ToolCapability.SCRIPT_EXECUTE,
    ),
)

FLAG_PERSONA = PersonaSpec(
    name="flag-worker",
    routing_summary="Harvests and validates concrete flag candidates.",
    allowed_capabilities=(
        ToolCapability.FLAG_HARVEST,
        ToolCapability.SCRIPT_EXECUTE,
    ),
)

ALL_PERSONAS: tuple[PersonaSpec, ...] = (
    RECON_PERSONA,
    ARTIFACT_PERSONA,
    WEB_PERSONA,
    EXPLOIT_PERSONA,
    FLAG_PERSONA,
)

__all__ = [
    "ALL_PERSONAS",
    "ARTIFACT_PERSONA",
    "EXPLOIT_PERSONA",
    "FLAG_PERSONA",
    "Persona",
    "PersonaSpec",
    "RECON_PERSONA",
    "WEB_PERSONA",
]
