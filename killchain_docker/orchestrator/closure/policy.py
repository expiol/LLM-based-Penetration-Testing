"""Deterministic routing policy for generated-artifact closure work."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch.types import AgentDirectoryView
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoItem

FINAL_DETERMINISTIC_CAPABILITIES = frozenset(
    {"artifact.triage", "disk.extract", "media.scan", "office.inspect", "png.inspect"}
)


class DeterministicClosurePolicy:
    """Dispatch rules for generated-artifact closure work."""

    @classmethod
    def has_generated_artifact(cls, state) -> bool:
        return ArtifactProjectionStore(state).has_generated_artifact()

    @classmethod
    def is_final_closure_todo(cls, planned_todo) -> bool:
        context = planned_todo.context or {}
        if str(context.get("family") or "") != "artifact-followup":
            return False
        intent = DispatchIntent.from_context(context)
        capability = str(intent.required_capability or "").strip()
        if capability not in FINAL_DETERMINISTIC_CAPABILITIES:
            return False
        paths = cls.todo_paths(context)
        if not paths:
            return False
        return all(("/.autopentest_artifacts/" in path for path in paths))

    @staticmethod
    def todo_paths(context: dict[str, object]) -> list[str]:
        paths: list[str] = []
        for key in ("path", "artifact_path", "file_path"):
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                paths.append(value.strip())
        raw_paths = context.get("paths")
        if isinstance(raw_paths, list):
            paths.extend((str(item).strip() for item in raw_paths if str(item).strip()))
        seen: set[str] = set()
        unique: list[str] = []
        for path in paths:
            if path not in seen:
                unique.append(path)
                seen.add(path)
        return unique

    @staticmethod
    def select_worker(
        *, todo: TodoItem, state, agent_directory: AgentDirectoryView
    ) -> tuple[object | None, str, str]:
        intent = DispatchIntent.from_context(todo.context)
        capability = str(intent.required_capability or "").strip()
        candidates = agent_directory.workers_for_capability(capability)
        if "artifact-worker" in candidates:
            candidates = [
                "artifact-worker",
                *[name for name in candidates if name != "artifact-worker"],
            ]
        last_reason = ""
        for worker_name in candidates:
            worker, reason = agent_directory.select(worker_name, todo, state)
            if worker is not None:
                return (worker, worker_name, "")
            last_reason = reason
        if candidates and last_reason:
            return (None, candidates[0], last_reason)
        return (
            None,
            candidates[0] if candidates else "",
            f"no worker supports required capability {capability!r}",
        )


__all__ = ["DeterministicClosurePolicy", "FINAL_DETERMINISTIC_CAPABILITIES"]
