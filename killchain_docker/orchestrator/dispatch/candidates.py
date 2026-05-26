"""Structural worker-candidate ordering for dispatch."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch.types import AgentDirectoryView
from killchain_docker.orchestrator.dispatch.signals import (
    active_exploit_closure,
    todo_has_file_signal,
    todo_has_web_signal,
)
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoItem, TodoPhase
from killchain_docker.tools.capabilities import (
    is_active_exploit_profile,
    is_universal_capability,
    worker_preferences_for_capability,
    worker_preferences_for_profile,
)


class DispatchRoutePolicy:
    """Structural worker preferences for one Planner Todo."""

    @classmethod
    def worker_candidates(
        cls, todo: TodoItem, agent_directory: AgentDirectoryView
    ) -> list[tuple[str, str]]:
        candidates: list[tuple[str, str]] = []
        intent = DispatchIntent.from_context(todo.context)
        if intent.profile and intent.profile != "open":
            candidates.extend(
                cls._profile_candidates(intent.profile, todo, agent_directory)
            )
        capability = str(intent.required_capability or "").strip()
        if capability and (not is_universal_capability(capability)):
            candidates.extend(
                cls._ordered_capability_candidates(capability, agent_directory)
            )
        for allowed in intent.allowed_capabilities:
            if is_universal_capability(allowed):
                continue
            candidates.extend(
                cls._ordered_capability_candidates(
                    allowed, agent_directory, allowed=True
                )
            )
        has_web_signal = todo_has_web_signal(todo)
        has_file_signal = todo_has_file_signal(todo)
        if has_web_signal and todo.phase == TodoPhase.RECON:
            candidates.append(
                ("recon-worker", "Structural: scope or service discovery context.")
            )
        if todo.phase == TodoPhase.EXPLOIT:
            candidates.append(("exploit-worker", "Structural: exploit phase."))
        if has_file_signal:
            candidates.append(("artifact-worker", "Structural: file/artifact context."))
        if has_web_signal and todo.phase != TodoPhase.RECON:
            candidates.append(("web-worker", "Structural: web/service context."))
        return cls._unique_available(candidates, agent_directory.worker_names)

    @staticmethod
    def _profile_candidates(
        profile: str, todo: TodoItem, agent_directory: AgentDirectoryView
    ) -> list[tuple[str, str]]:
        if profile == "execution_closure" and active_exploit_closure(todo):
            indexed = agent_directory.workers_for_profile(profile)
            ordered = [
                name
                for name in ("exploit-worker", "artifact-worker")
                if name in indexed
            ]
            ordered.extend((name for name in indexed if name not in ordered))
            return [
                (name, f"Structural: active execution closure profile {profile}.")
                for name in ordered
            ]
        if todo.phase == TodoPhase.EXPLOIT and (not is_active_exploit_profile(profile)):
            return [
                (
                    "exploit-worker",
                    f"Structural: exploit phase overrides passive dispatch profile {profile}.",
                ),
                *DispatchRoutePolicy._ordered_profile_candidates(
                    profile, agent_directory
                ),
            ]
        return DispatchRoutePolicy._ordered_profile_candidates(profile, agent_directory)

    @staticmethod
    def _ordered_profile_candidates(
        profile: str, agent_directory: AgentDirectoryView
    ) -> list[tuple[str, str]]:
        indexed = agent_directory.workers_for_profile(profile)
        preferred = worker_preferences_for_profile(profile)
        ordered = [name for name in preferred if name in indexed] + [
            name for name in indexed if name not in preferred
        ]
        return [(name, f"Structural: dispatch profile {profile}.") for name in ordered]

    @staticmethod
    def _ordered_capability_candidates(
        capability: str, agent_directory: AgentDirectoryView, *, allowed: bool = False
    ) -> list[tuple[str, str]]:
        indexed = agent_directory.workers_for_capability(capability)
        preferred = worker_preferences_for_capability(capability)
        ordered = [name for name in preferred if name in indexed] + [
            name for name in indexed if name not in preferred
        ]
        kind = "allowed" if allowed else "required"
        return [
            (name, f"Structural: {kind} capability {capability}.") for name in ordered
        ]

    @staticmethod
    def _unique_available(
        candidates: list[tuple[str, str]], worker_names: set[str]
    ) -> list[tuple[str, str]]:
        seen: set[str] = set()
        unique: list[tuple[str, str]] = []
        for worker_name, rationale in candidates:
            if worker_name in seen or worker_name not in worker_names:
                continue
            seen.add(worker_name)
            unique.append((worker_name, rationale))
        return unique


__all__ = ["DispatchRoutePolicy"]
