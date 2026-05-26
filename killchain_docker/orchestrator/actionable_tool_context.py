"""Normalize concrete tool hints from artifact-oriented todo context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.goal_predicates import (
    goal_requires_artifact_extraction,
    goal_requires_binary_static_analysis,
    goal_requires_executable_interaction,
    goal_requires_raw_artifact_access,
)
from killchain_docker.orchestrator.todo_dispatch_intent import (
    dispatch_profile,
    set_required_capability,
)
from killchain_docker.state.todos import TodoPhase

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo


def apply_actionable_tool_context(
    todo: "PlannedTodo", context: dict[str, object], family: str
) -> None:
    del family
    goal_l = todo.goal.lower()
    if not has_artifact_triage_intent(context):
        return
    if todo.phase == TodoPhase.EXPLOIT and goal_requires_executable_interaction(goal_l):
        set_required_capability(
            context, profile="execution_closure", capability="script.exec"
        )
        return
    if goal_requires_raw_artifact_access(goal_l):
        set_required_capability(
            context,
            profile=dispatch_profile(context, default="artifact_analysis"),
            capability="shell.exec",
        )
        return
    if goal_requires_binary_static_analysis(goal_l):
        set_required_capability(
            context, profile="binary_analysis", capability="shell.exec"
        )
        return
    if goal_requires_artifact_extraction(goal_l):
        set_required_capability(
            context, profile="container_extraction", capability="shell.exec"
        )


def has_artifact_triage_intent(context: dict[str, object]) -> bool:
    raw_intent = context.get("dispatch_intent")
    required = ""
    if isinstance(raw_intent, dict):
        required = str(raw_intent.get("required_capability") or "").strip().lower()
    return required == "artifact.triage"
