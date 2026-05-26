"""Novelty checks for repeated planner todo families."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.progress_families import todo_family
from killchain_docker.orchestrator.round_result_signals import NO_PROGRESS_QUALITIES
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
        item.context for item in TodoQueueReader(state).by_family(family, todo_family)
    ]
    return GroundingProjection(state).has_new_fact_refs(
        filtered_context, previous_contexts, "evidence_id", "evidence_ids"
    )


def evidence_ref_can_unlock_progress(state: "RunState", evidence_id: str) -> bool:
    evidence = state.evidence.get(evidence_id)
    if evidence is None:
        return False
    extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
    ctx = extracted.get("output_context")
    ctx = ctx if isinstance(ctx, dict) else {}
    if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
        return True
    if (
        ctx.get("generated_artifacts_durable")
        or ctx.get("generated_artifact_records")
        or ctx.get("extracted_files_durable")
        or ctx.get("extracted_file_records")
    ):
        return True
    quality_tokens = {
        str(ctx.get("result_quality") or "").strip().lower(),
        str(ctx.get("failure_kind") or "").strip().lower(),
    }
    quality_tokens.discard("")
    if quality_tokens and quality_tokens <= NO_PROGRESS_QUALITIES:
        return False
    return True


def has_new_fact_refs(
    todo: "PlannedTodo", state: "RunState", family: str, *keys: str
) -> bool:
    previous_contexts = [
        item.context for item in TodoQueueReader(state).by_family(family, todo_family)
    ]
    return GroundingProjection(state).has_new_fact_refs(
        todo.context, previous_contexts, *keys
    )
