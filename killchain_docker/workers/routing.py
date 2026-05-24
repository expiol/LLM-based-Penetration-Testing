"""Persona Worker eligibility policy for routed Planner Todos."""

from __future__ import annotations

from typing import Protocol

from killchain_docker.state import DispatchIntent, RunState, TodoItem
from killchain_docker.tools import ToolCapability


class WorkerRouteView(Protocol):
    """Read-only Persona Worker view needed for routing eligibility."""

    name: str
    required_context_keys: tuple[str, ...]

    @property
    def allowed_capabilities(self) -> tuple[ToolCapability, ...]: ...

    def supports(self, todo: TodoItem) -> bool: ...


class PersonaRoutingPolicy:
    """Eligibility rules applied after the Router selects a Persona Worker."""

    @classmethod
    def can_route_task(
        cls,
        worker: WorkerRouteView,
        todo: TodoItem,
        state: RunState,
    ) -> tuple[bool, str | None]:
        del state
        if not worker.supports(todo):
            return False, "todo not supported"

        context = todo.context
        if worker.name in cls._excluded_workers(context):
            return False, "worker explicitly excluded by task metadata"

        missing_capability = cls._missing_required_capability(worker, context)
        if missing_capability:
            return False, f"missing required capability: {missing_capability}"

        for key in worker.required_context_keys:
            value = context.get(key)
            if value in (None, "", [], {}, ()):
                return False, f"missing required context key: {key}"
        return True, None

    @staticmethod
    def _excluded_workers(context: dict[str, object]) -> set[str]:
        return {
            str(value)
            for value in (context.get("exclude_workers") or [])
        }

    @staticmethod
    def _missing_required_capability(
        worker: WorkerRouteView,
        context: dict[str, object],
    ) -> str | None:
        intent = DispatchIntent.from_context(context)
        if (
            not intent.required_capability
            or intent.required_capability in {"shell.exec", "script.exec"}
        ):
            return None
        known_capabilities = {capability.value for capability in ToolCapability}
        if intent.required_capability not in known_capabilities:
            return None
        allowed = {
            capability.value if hasattr(capability, "value") else str(capability)
            for capability in worker.allowed_capabilities
        }
        if intent.required_capability not in allowed:
            return intent.required_capability
        return None
