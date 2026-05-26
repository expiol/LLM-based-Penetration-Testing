"""Capability enum, tool specs, and gateway.

Each ToolCapability maps 1:1 to a registered plugin.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from killchain_docker.tools.core import (
    ExecutionPlane,
    ToolExecutionBundle,
    ToolExecutionPolicy,
    ToolExecutionRequest,
    ToolInterruptBehavior,
)


class ToolCapability(StrEnum):
    # Universal low-level
    SHELL_EXEC = "shell.exec"
    SCRIPT_EXEC = "script.exec"

    # Network recon
    NMAP = "nmap"
    CURL = "curl"
    NIKTO = "nikto"
    SQLMAP = "sqlmap"

    # Binary / file analysis
    ARTIFACT_TRIAGE = "artifact.triage"
    DISK_EXTRACT = "disk.extract"
    FILE_CMD = "file_cmd"
    STRINGS_CMD = "strings_cmd"
    BINWALK = "binwalk"
    RADARE2 = "radare2"
    OBJDUMP = "objdump"
    GDB = "gdb"
    CHECKSEC = "checksec"
    LTRACE = "ltrace"
    STRACE = "strace"

    # Forensics / stego
    TSHARK = "tshark"
    OFFICE_INSPECT = "office.inspect"
    MEDIA_SCAN = "media.scan"
    PNG_INSPECT = "png.inspect"
    EXIFTOOL = "exiftool"
    STEGHIDE = "steghide"
    FOREMOST = "foremost"

    # Database
    SQLITE3 = "sqlite3"

    # Crypto / cracking
    JOHN = "john"
    FCRACKZIP = "fcrackzip"

    # APK / Java
    JADX = "jadx"


@dataclass(frozen=True)
class ToolSpec:
    """Runtime contract for one capability.

    This is the Python counterpart of the reference project's Tool protocol:
    callers learn execution binding, dispatch profile, routing preference, and
    direct-run behavior from one catalog entry instead of duplicating those
    facts in planner, router, and worker code.
    """

    capability: ToolCapability
    tool_name: str
    default_timeout_s: int = 120
    dispatch_profile: str = "open"
    worker_preferences: tuple[str, ...] = ()
    direct: bool = False
    universal: bool = False
    read_only: bool = False
    concurrency_safe: bool = False
    destructive: bool = False
    max_output_bytes: int | None = None
    interrupt_behavior: ToolInterruptBehavior = ToolInterruptBehavior.CANCEL

    def execution_policy(self) -> ToolExecutionPolicy:
        return ToolExecutionPolicy(
            read_only=self.read_only,
            concurrency_safe=self.concurrency_safe,
            destructive=self.destructive,
            interrupt_behavior=self.interrupt_behavior,
            max_output_bytes=self.max_output_bytes,
        )


@dataclass(frozen=True)
class DispatchProfileSpec:
    """Routing contract for a semantic dispatch profile."""

    profile: str
    worker_preferences: tuple[str, ...] = ()
    active_exploit: bool = False


# Auto-generate specs: capability value == plugin name for all CLI tools.
# Shell and script have separate plugin names.
DEFAULT_TOOL_SPECS: dict[ToolCapability, ToolSpec] = {
    ToolCapability.SHELL_EXEC: ToolSpec(
        ToolCapability.SHELL_EXEC,
        "shell_exec",
        universal=True,
        destructive=True,
    ),
    ToolCapability.SCRIPT_EXEC: ToolSpec(
        ToolCapability.SCRIPT_EXEC,
        "script_exec",
        universal=True,
        destructive=True,
    ),
    ToolCapability.NMAP: ToolSpec(
        ToolCapability.NMAP,
        "nmap",
        dispatch_profile="scope_mapping",
        worker_preferences=("recon-worker", "exploit-worker"),
        read_only=True,
    ),
    ToolCapability.CURL: ToolSpec(
        ToolCapability.CURL,
        "curl",
        dispatch_profile="web_analysis",
        worker_preferences=(
            "web-worker",
            "recon-worker",
            "exploit-worker",
            "flag-worker",
        ),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.NIKTO: ToolSpec(
        ToolCapability.NIKTO,
        "nikto",
        dispatch_profile="web_analysis",
        worker_preferences=("web-worker", "recon-worker"),
        read_only=True,
    ),
    ToolCapability.SQLMAP: ToolSpec(
        ToolCapability.SQLMAP,
        "sqlmap",
        dispatch_profile="web_exploitation",
        worker_preferences=("web-worker", "exploit-worker"),
        read_only=True,
    ),
    ToolCapability.ARTIFACT_TRIAGE: ToolSpec(
        ToolCapability.ARTIFACT_TRIAGE,
        "artifact_triage",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker", "recon-worker", "flag-worker"),
        direct=True,
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.DISK_EXTRACT: ToolSpec(
        ToolCapability.DISK_EXTRACT,
        "disk_extract",
        default_timeout_s=180,
        dispatch_profile="container_extraction",
        worker_preferences=("artifact-worker",),
        direct=True,
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.OFFICE_INSPECT: ToolSpec(
        ToolCapability.OFFICE_INSPECT,
        "office_inspect",
        default_timeout_s=120,
        dispatch_profile="office_inspection",
        worker_preferences=("artifact-worker",),
        direct=True,
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.MEDIA_SCAN: ToolSpec(
        ToolCapability.MEDIA_SCAN,
        "media_scan",
        default_timeout_s=120,
        dispatch_profile="media_inspection",
        worker_preferences=("artifact-worker",),
        direct=True,
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.PNG_INSPECT: ToolSpec(
        ToolCapability.PNG_INSPECT,
        "png_inspect",
        default_timeout_s=120,
        dispatch_profile="image_inspection",
        worker_preferences=("artifact-worker",),
        direct=True,
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.FILE_CMD: ToolSpec(
        ToolCapability.FILE_CMD,
        "file_cmd",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker", "recon-worker", "flag-worker"),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.STRINGS_CMD: ToolSpec(
        ToolCapability.STRINGS_CMD,
        "strings_cmd",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker", "flag-worker", "exploit-worker"),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.BINWALK: ToolSpec(
        ToolCapability.BINWALK,
        "binwalk",
        dispatch_profile="container_extraction",
        worker_preferences=("artifact-worker",),
        read_only=True,
    ),
    ToolCapability.RADARE2: ToolSpec(
        ToolCapability.RADARE2,
        "radare2",
        dispatch_profile="binary_analysis",
        worker_preferences=("artifact-worker", "exploit-worker"),
        read_only=True,
    ),
    ToolCapability.OBJDUMP: ToolSpec(
        ToolCapability.OBJDUMP,
        "objdump",
        dispatch_profile="binary_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.GDB: ToolSpec(
        ToolCapability.GDB,
        "gdb",
        dispatch_profile="binary_analysis",
        worker_preferences=("exploit-worker", "artifact-worker"),
        read_only=True,
    ),
    ToolCapability.CHECKSEC: ToolSpec(
        ToolCapability.CHECKSEC,
        "checksec",
        dispatch_profile="binary_analysis",
        worker_preferences=("artifact-worker", "exploit-worker"),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.LTRACE: ToolSpec(
        ToolCapability.LTRACE,
        "ltrace",
        dispatch_profile="binary_analysis",
        worker_preferences=("artifact-worker", "exploit-worker"),
        read_only=True,
    ),
    ToolCapability.STRACE: ToolSpec(
        ToolCapability.STRACE,
        "strace",
        dispatch_profile="binary_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
    ),
    ToolCapability.TSHARK: ToolSpec(
        ToolCapability.TSHARK,
        "tshark",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.EXIFTOOL: ToolSpec(
        ToolCapability.EXIFTOOL,
        "exiftool",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker", "recon-worker"),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.STEGHIDE: ToolSpec(
        ToolCapability.STEGHIDE,
        "steghide",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
    ),
    ToolCapability.FOREMOST: ToolSpec(
        ToolCapability.FOREMOST,
        "foremost",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
    ),
    ToolCapability.SQLITE3: ToolSpec(
        ToolCapability.SQLITE3,
        "sqlite3",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker", "web-worker", "flag-worker"),
        read_only=True,
        concurrency_safe=True,
    ),
    ToolCapability.JOHN: ToolSpec(
        ToolCapability.JOHN,
        "john",
        dispatch_profile="credential_recovery",
        worker_preferences=("exploit-worker",),
        read_only=True,
    ),
    ToolCapability.FCRACKZIP: ToolSpec(
        ToolCapability.FCRACKZIP,
        "fcrackzip",
        dispatch_profile="credential_recovery",
        worker_preferences=("exploit-worker",),
        read_only=True,
    ),
    ToolCapability.JADX: ToolSpec(
        ToolCapability.JADX,
        "jadx",
        dispatch_profile="artifact_analysis",
        worker_preferences=("artifact-worker",),
        read_only=True,
        concurrency_safe=True,
    ),
}
for _cap in ToolCapability:
    if _cap not in DEFAULT_TOOL_SPECS:
        DEFAULT_TOOL_SPECS[_cap] = ToolSpec(_cap, _cap.value)


DEFAULT_DISPATCH_PROFILE_SPECS: dict[str, DispatchProfileSpec] = {
    "scope_mapping": DispatchProfileSpec(
        "scope_mapping",
        worker_preferences=("recon-worker", "web-worker"),
    ),
    "recon": DispatchProfileSpec(
        "recon",
        worker_preferences=("recon-worker", "artifact-worker"),
    ),
    "artifact_analysis": DispatchProfileSpec(
        "artifact_analysis",
        worker_preferences=("artifact-worker", "recon-worker"),
    ),
    "container_extraction": DispatchProfileSpec(
        "container_extraction",
        worker_preferences=("artifact-worker",),
    ),
    "office_inspection": DispatchProfileSpec(
        "office_inspection",
        worker_preferences=("artifact-worker",),
    ),
    "media_inspection": DispatchProfileSpec(
        "media_inspection",
        worker_preferences=("artifact-worker",),
    ),
    "image_inspection": DispatchProfileSpec(
        "image_inspection",
        worker_preferences=("artifact-worker",),
    ),
    "near_miss_repair": DispatchProfileSpec(
        "near_miss_repair",
        worker_preferences=("artifact-worker", "exploit-worker"),
    ),
    "execution_closure": DispatchProfileSpec(
        "execution_closure",
        worker_preferences=("artifact-worker", "exploit-worker"),
        active_exploit=True,
    ),
    "execution_continuation": DispatchProfileSpec(
        "execution_continuation",
        worker_preferences=("exploit-worker", "artifact-worker"),
        active_exploit=True,
    ),
    "algorithm_verification": DispatchProfileSpec(
        "algorithm_verification",
        worker_preferences=("artifact-worker", "exploit-worker"),
    ),
    "binary_analysis": DispatchProfileSpec(
        "binary_analysis",
        worker_preferences=("artifact-worker", "exploit-worker"),
    ),
    "web_analysis": DispatchProfileSpec(
        "web_analysis",
        worker_preferences=("web-worker", "recon-worker"),
    ),
    "web_exploitation": DispatchProfileSpec(
        "web_exploitation",
        worker_preferences=("web-worker", "exploit-worker"),
        active_exploit=True,
    ),
    "exploit": DispatchProfileSpec(
        "exploit",
        worker_preferences=("exploit-worker",),
        active_exploit=True,
    ),
    "pwn_exploit": DispatchProfileSpec(
        "pwn_exploit",
        worker_preferences=("exploit-worker", "artifact-worker"),
        active_exploit=True,
    ),
    "credential_recovery": DispatchProfileSpec(
        "credential_recovery",
        worker_preferences=("exploit-worker",),
        active_exploit=True,
    ),
    "candidate_recovery": DispatchProfileSpec(
        "candidate_recovery",
        worker_preferences=("artifact-worker", "exploit-worker"),
    ),
    "flag_validation": DispatchProfileSpec(
        "flag_validation",
        worker_preferences=("flag-worker",),
    ),
}

_FAMILY_DISPATCH_PROFILES: dict[str, str] = {
    "algorithm-verification": "algorithm_verification",
    "artifact-followup": "artifact_analysis",
    "artifact-inventory": "artifact_analysis",
    "binary-analysis": "binary_analysis",
    "binary-dynamic": "binary_analysis",
    "binary-run": "binary_analysis",
    "binary-static": "binary_analysis",
    "candidate-recovery": "candidate_recovery",
    "crypto-decrypt": "algorithm_verification",
    "crypto-model": "algorithm_verification",
    "execution-continuation": "execution_continuation",
    "flag-recovery": "candidate_recovery",
    "flag-validation": "flag_validation",
    "forensics-extract": "container_extraction",
    "pwn-exploit": "pwn_exploit",
    "pwn-surface": "binary_analysis",
    "recon": "recon",
    "source-review": "artifact_analysis",
    "web-exploit": "web_exploitation",
    "web-surface": "web_analysis",
}


def normalize_dispatch_profile(profile: object) -> str:
    """Return a catalog-owned dispatch profile, or ``open`` for unknown input."""

    normalized = (
        str(profile or "open").strip().lower().replace("-", "_").replace(" ", "_")
    )
    if normalized in DEFAULT_DISPATCH_PROFILE_SPECS:
        return normalized
    return "open"


def normalize_dispatch_family(family: object) -> str:
    """Normalize semantic todo family names for catalog lookup."""

    return str(family or "").strip().lower()


def dispatch_profile_for_family(family: object) -> str:
    """Return the default dispatch profile for a semantic todo family."""

    return _FAMILY_DISPATCH_PROFILES.get(normalize_dispatch_family(family), "open")


def dispatch_profile_spec(profile: object) -> DispatchProfileSpec | None:
    """Return the catalog entry for a normalized dispatch profile."""

    return DEFAULT_DISPATCH_PROFILE_SPECS.get(normalize_dispatch_profile(profile))


def worker_preferences_for_profile(profile: object) -> tuple[str, ...]:
    """Return persona-worker preferences attached to a dispatch profile."""

    spec = dispatch_profile_spec(profile)
    return spec.worker_preferences if spec else ()


def supported_profiles_for_worker(worker_name: str) -> tuple[str, ...]:
    """Return dispatch profiles that list a worker in their preferences."""

    name = str(worker_name or "").strip()
    if not name:
        return ()
    profiles = [
        profile
        for profile, spec in DEFAULT_DISPATCH_PROFILE_SPECS.items()
        if name in spec.worker_preferences
    ]
    if name != "flag-worker":
        profiles.insert(0, "open")
    return tuple(dict.fromkeys(profiles))


def is_active_exploit_profile(profile: object) -> bool:
    """Return whether a dispatch profile represents active exploitation."""

    spec = dispatch_profile_spec(profile)
    return bool(spec and spec.active_exploit)


def tool_spec(capability: ToolCapability | str) -> ToolSpec | None:
    """Return the catalog entry for a capability value, if known."""

    try:
        cap = ToolCapability(capability)
    except ValueError:
        return None
    return DEFAULT_TOOL_SPECS.get(cap)


def dispatch_profile_for_capability(capability: ToolCapability | str | None) -> str:
    """Return the default dispatch profile attached to a capability."""

    if not capability:
        return "open"
    spec = tool_spec(capability)
    return spec.dispatch_profile if spec else "open"


def worker_preferences_for_capability(
    capability: ToolCapability | str,
) -> tuple[str, ...]:
    """Return persona-worker preferences attached to a capability."""

    spec = tool_spec(capability)
    return spec.worker_preferences if spec else ()


def is_universal_capability(capability: ToolCapability | str | None) -> bool:
    """Return whether a capability is intentionally available to all personas."""

    if not capability:
        return False
    spec = tool_spec(capability)
    return bool(spec and spec.universal)


def direct_tool_capabilities() -> frozenset[ToolCapability]:
    """Capabilities whose metadata can be prepared and run without LLM choice."""

    return frozenset(
        capability for capability, spec in DEFAULT_TOOL_SPECS.items() if spec.direct
    )


class ToolGateway:
    """Route capability requests to the execution plane."""

    def __init__(
        self,
        execution_plane: ExecutionPlane,
        *,
        specs: dict[ToolCapability, ToolSpec] | None = None,
    ) -> None:
        self.execution_plane = execution_plane
        self.specs = dict(specs or DEFAULT_TOOL_SPECS)

    def run(
        self,
        *,
        task_id: str,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle:
        cap = ToolCapability(capability)
        spec = self.specs[cap]
        request = ToolExecutionRequest(
            capability=cap.value,
            tool_name=spec.tool_name,
            timeout_s=timeout_s or spec.default_timeout_s,
            metadata=metadata,
            policy=spec.execution_policy(),
        )
        return self.execution_plane.execute(task_id, request)
