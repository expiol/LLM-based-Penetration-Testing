"""Persona protocol and worker architecture.

A Persona defines the strategy for a worker: which capabilities it can use,
how it prepares metadata, and any custom post-processing. The Worker class
provides the shared execution loop; persona differences are data + strategy,
not separate class hierarchies.

Each persona gets shell.exec + script.exec as universal fallbacks, plus
domain-specific high-level tools.
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


# Universal capabilities available to every persona
_UNIVERSAL: tuple[ToolCapability, ...] = (
    ToolCapability.SHELL_EXEC,
    ToolCapability.SCRIPT_EXEC,
)


@dataclass(frozen=True)
class PersonaSpec:
    """Concrete persona specification — data, not code."""

    name: str
    allowed_capabilities: tuple[ToolCapability, ...] = _UNIVERSAL
    routing_summary: str = ""
    supported_todo_kinds: tuple[str, ...] = ("todo",)
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Predefined persona specs
# ---------------------------------------------------------------------------

RECON_PERSONA = PersonaSpec(
    name="recon-worker",
    allowed_capabilities=_UNIVERSAL + (
        ToolCapability.NMAP,
        ToolCapability.CURL,
        ToolCapability.NIKTO,
        ToolCapability.FILE_CMD,
        ToolCapability.EXIFTOOL,
    ),
    routing_summary=(
        "Maps authorized scope: port scans (nmap), HTTP recon (curl, nikto), "
        "file identification (file, exiftool). First-pass discovery only."
    ),
)

ARTIFACT_PERSONA = PersonaSpec(
    name="artifact-worker",
    allowed_capabilities=_UNIVERSAL + (
        ToolCapability.FILE_CMD,
        ToolCapability.STRINGS_CMD,
        ToolCapability.BINWALK,
        ToolCapability.RADARE2,
        ToolCapability.OBJDUMP,
        ToolCapability.GDB,
        ToolCapability.TSHARK,
        ToolCapability.EXIFTOOL,
        ToolCapability.STEGHIDE,
        ToolCapability.FOREMOST,
        ToolCapability.SQLITE3,
        ToolCapability.JADX,
    ),
    routing_summary=(
        "Static file analysis: binaries (r2, objdump, gdb, strings), firmware (binwalk), "
        "pcaps (tshark), databases (sqlite3), stego (steghide, foremost, exiftool), "
        "APKs (jadx). Offline analysis, no network interaction."
    ),
    preferred_challenge_categories=("crypto", "rev", "forensics", "misc", "pwn", "web"),
)

WEB_PERSONA = PersonaSpec(
    name="web-worker",
    allowed_capabilities=_UNIVERSAL + (
        ToolCapability.CURL,
        ToolCapability.NIKTO,
        ToolCapability.SQLMAP,
        ToolCapability.SQLITE3,
    ),
    routing_summary=(
        "Web exploitation: HTTP requests (curl), vulnerability scanning (nikto), "
        "SQL injection (sqlmap), database extraction (sqlite3). "
        "Operates within authorized scope."
    ),
    preferred_challenge_categories=("web",),
)

EXPLOIT_PERSONA = PersonaSpec(
    name="exploit-worker",
    allowed_capabilities=_UNIVERSAL + (
        ToolCapability.NMAP,
        ToolCapability.CURL,
        ToolCapability.SQLMAP,
        ToolCapability.GDB,
        ToolCapability.JOHN,
        ToolCapability.FCRACKZIP,
        ToolCapability.STRINGS_CMD,
        ToolCapability.RADARE2,
    ),
    routing_summary=(
        "Active exploitation: credential attacks (john, fcrackzip), SQL injection (sqlmap), "
        "binary exploitation (gdb, r2), network probing (nmap, curl). "
        "Runs bounded experiments from accumulated evidence."
    ),
)

FLAG_PERSONA = PersonaSpec(
    name="flag-worker",
    allowed_capabilities=_UNIVERSAL + (
        ToolCapability.STRINGS_CMD,
        ToolCapability.FILE_CMD,
        ToolCapability.CURL,
        ToolCapability.SQLITE3,
    ),
    routing_summary=(
        "Flag harvesting: search files (strings, file), query databases (sqlite3), "
        "submit flags via HTTP (curl). Validates concrete flag candidates."
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
