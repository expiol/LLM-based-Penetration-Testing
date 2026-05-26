"""Persona specs for the worker runtime.

Persona identity is data: which capabilities a worker can use, how it should
be routed, and what challenge categories it prefers. The Worker class provides
the shared execution loop; persona differences live in frozen specs rather
than separate class hierarchies.

Each persona gets shell.exec + script.exec as universal base capabilities, plus
domain-specific high-level tools.
"""

from __future__ import annotations

from dataclasses import dataclass

from killchain_docker.rag.augmenter import RagAugmenter
from killchain_docker.llm.gateway import LLMClient
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ExecutionPlane


# Universal capabilities available to every persona
_UNIVERSAL: tuple[ToolCapability, ...] = (
    ToolCapability.SHELL_EXEC,
    ToolCapability.SCRIPT_EXEC,
)


@dataclass(frozen=True)
class PersonaSpec:
    """Concrete persona specification - data, not code."""

    name: str
    allowed_capabilities: tuple[ToolCapability, ...] = _UNIVERSAL
    routing_summary: str = ""
    supported_todo_kinds: tuple[str, ...] = ("todo",)
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()
    supported_dispatch_profiles: tuple[str, ...] = ()


RECON_PERSONA = PersonaSpec(
    name="recon-worker",
    allowed_capabilities=_UNIVERSAL
    + (
        ToolCapability.NMAP,
        ToolCapability.CURL,
        ToolCapability.NIKTO,
        ToolCapability.ARTIFACT_TRIAGE,
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
    allowed_capabilities=_UNIVERSAL
    + (
        ToolCapability.FILE_CMD,
        ToolCapability.ARTIFACT_TRIAGE,
        ToolCapability.DISK_EXTRACT,
        ToolCapability.OFFICE_INSPECT,
        ToolCapability.MEDIA_SCAN,
        ToolCapability.PNG_INSPECT,
        ToolCapability.STRINGS_CMD,
        ToolCapability.BINWALK,
        ToolCapability.RADARE2,
        ToolCapability.OBJDUMP,
        ToolCapability.GDB,
        ToolCapability.CHECKSEC,
        ToolCapability.LTRACE,
        ToolCapability.STRACE,
        ToolCapability.TSHARK,
        ToolCapability.EXIFTOOL,
        ToolCapability.STEGHIDE,
        ToolCapability.FOREMOST,
        ToolCapability.SQLITE3,
        ToolCapability.JADX,
    ),
    routing_summary=(
        "Static and dynamic file analysis: binaries (r2, objdump, gdb, checksec, strings), "
        "dynamic tracing (ltrace, strace), firmware (binwalk), Office documents (office.inspect), "
        "embedded media batches (media.scan), PNG images (png.inspect), "
        "pcaps (tshark), databases (sqlite3), stego (steghide, foremost, exiftool), "
        "APKs (jadx). Supports both offline analysis and local binary execution."
    ),
    preferred_challenge_categories=("crypto", "rev", "forensics", "misc", "pwn", "web"),
)

WEB_PERSONA = PersonaSpec(
    name="web-worker",
    allowed_capabilities=_UNIVERSAL
    + (
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
    allowed_capabilities=_UNIVERSAL
    + (
        ToolCapability.NMAP,
        ToolCapability.CURL,
        ToolCapability.SQLMAP,
        ToolCapability.GDB,
        ToolCapability.CHECKSEC,
        ToolCapability.LTRACE,
        ToolCapability.JOHN,
        ToolCapability.FCRACKZIP,
        ToolCapability.STRINGS_CMD,
        ToolCapability.RADARE2,
    ),
    routing_summary=(
        "Active exploitation: credential attacks (john, fcrackzip), SQL injection (sqlmap), "
        "binary exploitation (gdb, checksec, ltrace, r2), network probing (nmap, curl). "
        "Runs bounded experiments from accumulated evidence."
    ),
)

FLAG_PERSONA = PersonaSpec(
    name="flag-worker",
    allowed_capabilities=_UNIVERSAL
    + (
        ToolCapability.STRINGS_CMD,
        ToolCapability.ARTIFACT_TRIAGE,
        ToolCapability.FILE_CMD,
        ToolCapability.CURL,
        ToolCapability.SQLITE3,
    ),
    routing_summary="Validates concrete flag candidates only.",
)

ALL_PERSONAS: tuple[PersonaSpec, ...] = (
    RECON_PERSONA,
    ARTIFACT_PERSONA,
    WEB_PERSONA,
    EXPLOIT_PERSONA,
    FLAG_PERSONA,
)


@dataclass(frozen=True)
class WorkerBuildContext:
    """Dependencies required to construct runtime persona workers."""

    llm_client: LLMClient
    execution_plane: ExecutionPlane
    augmenter: RagAugmenter | None = None
    expected_flag: str | None = None


def build_builtin_workers(context: WorkerBuildContext):
    """Build the runtime worker set from the persona catalog."""

    from killchain_docker.workers.runtime.worker import Worker

    return [
        Worker(
            persona=persona,
            llm_client=context.llm_client,
            execution_plane=context.execution_plane,
            expected_flag=context.expected_flag
            if persona.name == "flag-worker"
            else None,
        )
        for persona in ALL_PERSONAS
    ]


__all__ = [
    "ALL_PERSONAS",
    "ARTIFACT_PERSONA",
    "EXPLOIT_PERSONA",
    "FLAG_PERSONA",
    "PersonaSpec",
    "RECON_PERSONA",
    "WEB_PERSONA",
    "WorkerBuildContext",
    "build_builtin_workers",
]
