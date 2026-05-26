"""Novelty checks for repeated planner todo families."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.progress_families import todo_family_candidates
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.evidence_progress import evidence_ref_can_unlock_progress
from killchain_docker.state.grounding_projection import GroundingProjection

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


def has_new_novelty(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
    novelty = str(todo.context.get("novelty_key") or "").strip()
    if novelty:
        previous = {
            str(item.context.get("novelty_key") or "").strip()
            for item in _matching_family_todos(state, family)
        }
        if novelty in previous and not has_new_state_refs(todo, state, family):
            return False
    return has_new_state_refs(todo, state, family)


def has_new_state_refs(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
    return has_new_evidence_refs(todo, state, family) or has_new_fact_refs(
        todo, state, family, "hypothesis_id", "hypothesis_ids"
    )


def has_new_evidence_refs(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
    refs = GroundingProjection.context_values(todo.context, "evidence_id", "evidence_ids")
    if not refs:
        return False
    useful_refs = {ref for ref in refs if evidence_ref_can_unlock_progress(state, ref)}
    if not useful_refs:
        return False
    filtered_context = {**todo.context, "evidence_ids": sorted(useful_refs)}
    if "evidence_id" in filtered_context and filtered_context["evidence_id"] not in useful_refs:
        filtered_context.pop("evidence_id", None)
    previous_contexts = [
        item.context for item in _matching_family_todos(state, family)
    ]
    return GroundingProjection(state).has_new_fact_refs(
        filtered_context, previous_contexts, "evidence_id", "evidence_ids"
    )


def has_new_fact_refs(
    todo: "PlannedTodo", state: "RunState", family: str, *keys: str
) -> bool:
    previous_contexts = [
        item.context for item in _matching_family_todos(state, family)
    ]
    return GroundingProjection(state).has_new_fact_refs(
        todo.context, previous_contexts, *keys
    )


def _matching_family_todos(state: "RunState", family: str):
    return [
        todo
        for todo in TodoQueueReader(state).all()
        if family in todo_family_candidates(todo)
    ]
