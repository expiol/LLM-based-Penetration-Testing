"""Routing eligibility checks for worker agents."""

from __future__ import annotations

from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability


class WorkerRoutingMixin:
    name: str
    required_context_keys: tuple[str, ...]
    allowed_capabilities: tuple[ToolCapability, ...]

    def supports(self, todo: TodoItem) -> bool:
        return True

    def can_route_task(
        self, todo: TodoItem, state: RunState
    ) -> tuple[bool, str | None]:
        """Return whether the worker is eligible for a routed dispatch."""
        del state
        if not self.supports(todo):
            return (False, "todo not supported")
        context = todo.context
        excluded = {str(value) for value in context.get("exclude_workers") or []}
        if self.name in excluded:
            return (False, "worker explicitly excluded by task metadata")
        missing_capability = self._missing_required_capability(context)
        if missing_capability:
            return (False, f"missing required capability: {missing_capability}")
        for key in self.required_context_keys:
            value = context.get(key)
            if value in (None, "", [], {}, ()):
                return (False, f"missing required context key: {key}")
        return (True, None)

    def _missing_required_capability(self, context: dict[str, object]) -> str | None:
        intent = DispatchIntent.from_context(context)
        if not intent.required_capability or intent.required_capability in {
            "shell.exec",
            "script.exec",
        }:
            return None
        known_capabilities = {capability.value for capability in ToolCapability}
        if intent.required_capability not in known_capabilities:
            return None
        allowed = {
            capability.value if hasattr(capability, "value") else str(capability)
            for capability in self.allowed_capabilities
        }
        if intent.required_capability not in allowed:
            return intent.required_capability
        return None
