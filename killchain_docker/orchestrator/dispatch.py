"""Deterministic dispatch policy for Planner Todos.

This module owns the structural rules that translate Dispatch Intent and
todo signals into Persona Worker preferences. The Router remains the Adapter
that asks an LLM only when these rules do not decide the assignment.
"""

from __future__ import annotations

from typing import Protocol

from killchain_docker.state import DispatchIntent, TodoItem, TodoPhase


class WorkerDirectoryView(Protocol):
    @property
    def worker_names(self) -> set[str]: ...

    def workers_for_capability(self, capability: str) -> list[str]: ...

    def workers_for_profile(self, profile: str) -> list[str]: ...


_UNIVERSAL_CAPABILITY_HINTS = frozenset({"shell.exec", "script.exec"})

_CAPABILITY_WORKER_PREFERENCES: dict[str, tuple[str, ...]] = {
    "artifact.triage": ("artifact-worker", "recon-worker", "flag-worker"),
    "disk.extract": ("artifact-worker",),
    "office.inspect": ("artifact-worker",),
    "media.scan": ("artifact-worker",),
    "png.inspect": ("artifact-worker",),
    "file_cmd": ("artifact-worker", "recon-worker", "flag-worker"),
    "strings_cmd": ("artifact-worker", "flag-worker", "exploit-worker"),
    "binwalk": ("artifact-worker",),
    "radare2": ("artifact-worker", "exploit-worker"),
    "objdump": ("artifact-worker",),
    "gdb": ("exploit-worker", "artifact-worker"),
    "checksec": ("artifact-worker", "exploit-worker"),
    "ltrace": ("artifact-worker", "exploit-worker"),
    "strace": ("artifact-worker",),
    "tshark": ("artifact-worker",),
    "exiftool": ("artifact-worker", "recon-worker"),
    "steghide": ("artifact-worker",),
    "foremost": ("artifact-worker",),
    "sqlite3": ("artifact-worker", "web-worker", "flag-worker"),
    "jadx": ("artifact-worker",),
    "nmap": ("recon-worker", "exploit-worker"),
    "curl": ("web-worker", "recon-worker", "exploit-worker", "flag-worker"),
    "nikto": ("web-worker", "recon-worker"),
    "sqlmap": ("web-worker", "exploit-worker"),
    "john": ("exploit-worker",),
    "fcrackzip": ("exploit-worker",),
}

_PROFILE_WORKER_PREFERENCES: dict[str, tuple[str, ...]] = {
    "scope_mapping": ("recon-worker", "web-worker"),
    "recon": ("recon-worker", "artifact-worker"),
    "artifact_analysis": ("artifact-worker", "recon-worker", "flag-worker"),
    "container_extraction": ("artifact-worker",),
    "office_inspection": ("artifact-worker",),
    "media_inspection": ("artifact-worker",),
    "image_inspection": ("artifact-worker",),
    "near_miss_repair": ("artifact-worker", "exploit-worker"),
    "execution_closure": ("artifact-worker", "exploit-worker"),
    "algorithm_verification": ("artifact-worker", "exploit-worker"),
    "binary_analysis": ("artifact-worker", "exploit-worker"),
    "web_analysis": ("web-worker", "recon-worker"),
    "web_exploitation": ("web-worker", "exploit-worker"),
    "exploit": ("exploit-worker",),
    "credential_recovery": ("exploit-worker",),
    "candidate_recovery": ("artifact-worker", "exploit-worker"),
    "flag_validation": ("flag-worker",),
}

_FILE_CONTEXT_KEYS = frozenset({
    "artifact_id",
    "artifact_path",
    "binary_files",
    "challenge_files",
    "file_path",
    "files_root",
    "path",
    "paths",
    "source_files",
})
_WEB_CONTEXT_KEYS = frozenset({
    "base_url",
    "endpoint_id",
    "endpoint_ids",
    "hostname",
    "port",
    "scope",
    "url",
})
_FILE_TERMS = (
    "artifact", "binary", "bundle", "challenge file", "document", "file",
    "image", "pcap", "source", "zip",
)
_SCOPE_TERMS = ("authorized scope", "host", "http", "map scope", "port", "service", "url")


class DispatchRoutePolicy:
    """Structural worker preferences for one Planner Todo."""

    @classmethod
    def worker_candidates(
        cls,
        todo: TodoItem,
        worker_directory: WorkerDirectoryView,
    ) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        intent = DispatchIntent.from_context(todo.context)
        if intent.profile and intent.profile != "open":
            candidates.extend(
                cls._ordered_profile_candidates(intent.profile, worker_directory)
            )

        capability = str(intent.required_capability or "").strip()
        if capability and capability not in _UNIVERSAL_CAPABILITY_HINTS:
            candidates.extend(
                cls._ordered_capability_candidates(capability, worker_directory)
            )

        for allowed in intent.allowed_capabilities:
            if allowed in _UNIVERSAL_CAPABILITY_HINTS:
                continue
            candidates.extend(
                cls._ordered_capability_candidates(allowed, worker_directory, allowed=True)
            )

        if cls.todo_has_file_signal(todo):
            candidates.append(("artifact-worker", "Structural: file/artifact context."))
        if todo.phase == TodoPhase.EXPLOIT:
            candidates.append(("exploit-worker", "Structural: exploit phase."))
        if cls.todo_has_web_signal(todo):
            if todo.phase == TodoPhase.RECON:
                candidates.append(("recon-worker", "Structural: scope or service discovery context."))
            else:
                candidates.append(("web-worker", "Structural: web/service context."))

        return cls._unique_available(candidates, worker_directory.worker_names)

    @staticmethod
    def todo_has_file_signal(todo: TodoItem) -> bool:
        if _todo_has_context_key(todo, _FILE_CONTEXT_KEYS):
            return True
        text = _todo_text(todo)
        return any(term in text for term in _FILE_TERMS)

    @staticmethod
    def todo_has_web_signal(todo: TodoItem) -> bool:
        if _todo_has_context_key(todo, _WEB_CONTEXT_KEYS):
            return True
        text = _todo_text(todo)
        return any(term in text for term in _SCOPE_TERMS)

    @staticmethod
    def _ordered_profile_candidates(
        profile: str,
        worker_directory: WorkerDirectoryView,
    ) -> list[tuple[str, str]]:
        indexed = worker_directory.workers_for_profile(profile)
        preferred = _PROFILE_WORKER_PREFERENCES.get(profile, ())
        ordered = [name for name in preferred if name in indexed] + [
            name for name in indexed if name not in preferred
        ]
        return [
            (name, f"Structural: dispatch profile {profile}.")
            for name in ordered
        ]

    @staticmethod
    def _ordered_capability_candidates(
        capability: str,
        worker_directory: WorkerDirectoryView,
        *,
        allowed: bool = False,
    ) -> list[tuple[str, str]]:
        indexed = worker_directory.workers_for_capability(capability)
        preferred = _CAPABILITY_WORKER_PREFERENCES.get(capability, ())
        ordered = [name for name in preferred if name in indexed] + [
            name for name in indexed if name not in preferred
        ]
        kind = "allowed" if allowed else "required"
        return [
            (name, f"Structural: {kind} capability {capability}.")
            for name in ordered
        ]

    @staticmethod
    def _unique_available(
        candidates: list[tuple[str, str]],
        worker_names: set[str],
    ) -> list[tuple[str, str]]:
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for worker_name, rationale in candidates:
            if worker_name in seen or worker_name not in worker_names:
                continue
            seen.add(worker_name)
            unique.append((worker_name, rationale))
        return unique


def _todo_has_context_key(todo: TodoItem, keys: frozenset[str]) -> bool:
    for key in keys:
        value = todo.context.get(key)
        if value not in (None, "", [], {}, ()):
            return True
    return False


def _todo_text(todo: TodoItem) -> str:
    return " ".join([
        todo.goal,
        " ".join(todo.success_criteria),
        " ".join(todo.constraints),
    ]).lower()
