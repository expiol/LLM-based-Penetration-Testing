"""Planner access and filtering for deterministic closure passes."""

from __future__ import annotations

from collections.abc import Callable

from killchain_docker.orchestrator.closure_policy import DeterministicClosurePolicy
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.state.run_state import RunState


def planner_merge(planner: object) -> Callable[..., PlannerDecision] | None:
    pipeline = getattr(planner, "pipeline", None)
    merge = getattr(pipeline, "merge", None)
    return merge if callable(merge) else None


def closure_decision(
    *,
    state: RunState,
    planner: object,
    summary: str,
    note: str,
    limit: int,
) -> PlannerDecision | None:
    merge = planner_merge(planner)
    if merge is None:
        return None
    decision = merge(
        state,
        llm_decision=PlannerDecision(summary=summary, todos=[], notes=[note]),
    )
    filtered = [
        todo
        for todo in decision.todos
        if DeterministicClosurePolicy.is_final_closure_todo(todo)
    ][:limit]
    if not filtered:
        return None
    return PlannerDecision(summary=summary, todos=filtered, notes=decision.notes)
