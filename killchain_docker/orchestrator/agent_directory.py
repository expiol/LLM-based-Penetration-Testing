"""Typed catalog and selector for orchestrator-managed workers."""

from __future__ import annotations
from collections.abc import Iterable
from typing import TYPE_CHECKING
from killchain_docker.orchestrator.agent_lifecycle import AgentLifecycle

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState
    from killchain_docker.state.todos import TodoItem
    from killchain_docker.workers.runtime.agent import WorkerAgent


class AgentDirectory:
    """Typed catalog and selector for orchestrator-managed workers."""

    def __init__(
        self,
        *,
        workers: Iterable["WorkerAgent"],
        lifecycle: AgentLifecycle | None = None,
    ) -> None:
        self.lifecycle = lifecycle or AgentLifecycle()
        self._workers = {worker.name: worker for worker in workers}
        self._catalog = [
            self._catalog_entry(worker) for worker in self._workers.values()
        ]
        self._worker_names = {
            str(item.get("name") or "")
            for item in self._catalog
            if str(item.get("name") or "")
        }
        self._capability_index: dict[str, list[str]] = {}
        self._profile_index: dict[str, list[str]] = {}
        for item in self._catalog:
            worker_name = str(item.get("name") or "")
            if not worker_name:
                continue
            self.lifecycle.ensure(worker_name)
            for capability in item.get("allowed_capabilities") or []:
                self._capability_index.setdefault(str(capability), []).append(
                    worker_name
                )
            for profile in item.get("supported_dispatch_profiles") or []:
                self._profile_index.setdefault(str(profile), []).append(worker_name)

    @classmethod
    def from_workers(
        cls,
        workers: Iterable["WorkerAgent"],
        *,
        lifecycle: AgentLifecycle | None = None,
    ) -> "AgentDirectory":
        return cls(workers=workers, lifecycle=lifecycle)

    @staticmethod
    def _catalog_entry(worker: "WorkerAgent") -> dict[str, object]:
        capabilities = [
            capability.value if hasattr(capability, "value") else str(capability)
            for capability in getattr(worker, "allowed_capabilities", ()) or ()
        ]
        return {
            "name": worker.name,
            "supported_todo_kinds": list(worker.supported_todo_kinds),
            "routing_summary": worker.routing_summary,
            "required_context_keys": list(worker.required_context_keys),
            "preferred_challenge_categories": list(
                worker.preferred_challenge_categories
            ),
            "allowed_capabilities": sorted(capabilities),
            "supported_dispatch_profiles": sorted(
                getattr(worker, "supported_dispatch_profiles", ()) or ()
            ),
        }

    @property
    def worker_names(self) -> set[str]:
        return set(self._worker_names)

    def prompt_catalog(self) -> list[dict[str, object]]:
        return [dict(item) for item in self._catalog]

    def workers_for_capability(self, capability: str) -> list[str]:
        return list(self._capability_index.get(str(capability), []))

    def workers_for_profile(self, profile: str) -> list[str]:
        return list(self._profile_index.get(str(profile), []))

    def select(
        self, worker_name: str, todo: "TodoItem", state: "RunState"
    ) -> tuple["WorkerAgent | None", str]:
        worker = self._workers.get(worker_name)
        if worker is None:
            return (None, f"router selected unknown worker {worker_name!r}")
        allowed, reason = worker.can_route_task(todo, state)
        if not allowed:
            return (None, reason or "worker rejected todo")
        return (worker, "")
