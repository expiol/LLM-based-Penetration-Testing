"""Novelty checks for repeated planner todo families."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.progress_families import todo_family
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.grounding_projection import GroundingProjection

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


def has_new_novelty(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
    novelty = str(todo.context.get("novelty_key") or "").strip()
    if novelty:
        previous = {
            str(item.context.get("novelty_key") or "").strip()
            for item in TodoQueueReader(state).by_family(family, todo_family)
        }
        if novelty in previous and not has_new_state_refs(todo, state, family):
            return False
    return has_new_state_refs(todo, state, family)


def has_new_state_refs(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
    return has_new_fact_refs(todo, state, family, "evidence_ids") or has_new_fact_refs(
        todo, state, family, "hypothesis_id", "hypothesis_ids"
    )


def has_new_fact_refs(
    todo: "PlannedTodo", state: "RunState", family: str, *keys: str
) -> bool:
    previous_contexts = [
        item.context for item in TodoQueueReader(state).by_family(family, todo_family)
    ]
    return GroundingProjection(state).has_new_fact_refs(
        todo.context, previous_contexts, *keys
    )
