"""Worker tool-selection helpers."""

from __future__ import annotations

from typing import Any, Protocol

from killchain_docker.reasoning.schemas import ToolUseDecision
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability

ToolSelection = tuple[
    ToolCapability, dict[str, object], str, str | None, dict[str, str]
]


class ToolSelectionAgent(Protocol):
    name: str

    def choose_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        allowed_capabilities: list[ToolCapability | str] | None = None,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision: ...

    def choose_fixed_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        capability: ToolCapability | str,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision: ...


def choose_capability(
    agent: ToolSelectionAgent,
    todo: TodoItem,
    state: RunState,
    *,
    allowed_capabilities: tuple[ToolCapability, ...],
    prior_steps: list[dict[str, object]] | None = None,
) -> ToolSelection:
    decision = agent.choose_tool_use(
        task=todo,
        state=state,
        allowed_capabilities=list(allowed_capabilities),
        prior_steps=prior_steps,
    )
    return (
        ToolCapability(decision.capability),
        dict(decision.metadata),
        decision.rationale,
        decision.hypothesis,
        dict(decision.memory_updates) if decision.memory_updates else {},
    )


def choose_fixed_capability(
    agent: ToolSelectionAgent,
    capability: ToolCapability,
    todo: TodoItem,
    state: RunState,
    *,
    prior_steps: list[dict[str, object]] | None = None,
) -> ToolSelection:
    decision = agent.choose_fixed_tool_use(
        task=todo, state=state, capability=capability, prior_steps=prior_steps
    )
    return (
        capability,
        dict(decision.metadata),
        decision.rationale,
        decision.hypothesis,
        dict(decision.memory_updates) if decision.memory_updates else {},
    )


def fixed_llm_capability(
    todo: TodoItem, allowed_capabilities: tuple[ToolCapability, ...]
) -> ToolCapability | None:
    intent = DispatchIntent.from_context(todo.context)
    raw = str(intent.required_capability or "").strip()
    if not raw:
        return None
    try:
        capability = ToolCapability(raw)
    except ValueError:
        return None
    if capability not in {ToolCapability.SCRIPT_EXEC, ToolCapability.SHELL_EXEC}:
        return None
    if capability not in allowed_capabilities:
        return None
    return capability


__all__ = [
    "ToolSelection",
    "ToolSelectionAgent",
    "choose_capability",
    "choose_fixed_capability",
    "fixed_llm_capability",
]
