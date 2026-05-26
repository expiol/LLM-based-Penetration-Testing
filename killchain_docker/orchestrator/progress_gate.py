"""Planner todo progress gate."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.progress_families import (
    consecutive_failures_without_evidence,
    family_counts,
)
from killchain_docker.orchestrator.progress_limits import (
    CONSECUTIVE_FAILURE_CAP,
    FAILURE_COOLDOWN_THRESHOLD,
    MAX_FAMILY_ATTEMPTS,
    MAX_FLAG_VALIDATION_ATTEMPTS,
    UNCAPPED_FAMILIES,
)
from killchain_docker.orchestrator.progress_novelty import has_new_novelty
from killchain_docker.orchestrator.todo_family import (
    broad_family_candidates_for,
    family_candidates_for,
    family_for,
)
from killchain_docker.orchestrator.todo_path_predicates import has_context_path
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.grounding_projection import GroundingProjection
from killchain_docker.state.metadata import RunMetadataStore

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


def progress_allows(todo: "PlannedTodo", state: "RunState") -> tuple[bool, str]:
    family = str(todo.context.get("family") or family_for(todo.goal, todo.context))
    candidates = todo_family_candidates(todo, family)
    if todo.depends_on:
        candidates = {family}
    forced_pivot = RunMetadataStore(state).forced_pivot()
    if forced_pivot is not None:
        banned = {str(item) for item in forced_pivot.get("banned_families") or []}
        blocked = sorted(forced_pivot_family_candidates(todo, family) & banned)
        if blocked:
            return (
                False,
                f"family {blocked[0]!r} is BANNED by forced pivot #{forced_pivot.get('pivot_number', '?')}",
            )
    if "flag-validation" in candidates:
        total, _failed = family_counts(state, "flag-validation")
        return _flag_validation_allows(todo, state, total)
    for candidate in sorted(candidates):
        allowed, reason = _candidate_family_allows(todo, state, candidate)
        if not allowed:
            return (False, reason)
    return (True, "")


def _candidate_family_allows(
    todo: "PlannedTodo", state: "RunState", family: str
) -> tuple[bool, str]:
    total, failed = family_counts(state, family)
    if family in UNCAPPED_FAMILIES:
        consecutive = consecutive_failures_without_evidence(state, family)
        if consecutive >= CONSECUTIVE_FAILURE_CAP:
            return (
                False,
                f"family {family!r} bankrupt: {consecutive} consecutive failures without new evidence",
            )
        if failed < FAILURE_COOLDOWN_THRESHOLD:
            return (True, "")
        if has_new_novelty(todo, state, family):
            return (True, "")
        return (
            False,
            f"family {family!r} is in cooldown after {failed} failed/partial attempt(s)",
        )
    if total >= MAX_FAMILY_ATTEMPTS:
        if is_evidence_triggered_artifact_followup(todo, state, family):
            return (True, "")
        return (False, f"family {family!r} hit hard cap ({total} total attempts)")
    if failed < FAILURE_COOLDOWN_THRESHOLD:
        return (True, "")
    if has_new_novelty(todo, state, family):
        return (True, "")
    return (
        False,
        f"family {family!r} is in cooldown after {failed} failed/partial attempt(s)",
    )


def _flag_validation_allows(
    todo: "PlannedTodo", state: "RunState", total: int
) -> tuple[bool, str]:
    candidate_val = str(todo.context.get("candidate_flag") or "").strip()
    if candidate_val:
        same_candidate_count = sum(
            (
                1
                for t in TodoQueueReader(state).by_family(
                    "flag-validation",
                    lambda item: str(
                        item.context.get("family")
                        or family_for(item.goal, item.context)
                    ),
                )
                if str(t.context.get("candidate_flag") or "").strip() == candidate_val
            )
        )
        if same_candidate_count >= MAX_FLAG_VALIDATION_ATTEMPTS:
            return (
                False,
                f"candidate {candidate_val!r} already validated {same_candidate_count} time(s); propose a different candidate or set stop_run=true",
            )
        return (True, "")
    if total >= MAX_FLAG_VALIDATION_ATTEMPTS:
        return (
            False,
            f"family 'flag-validation' hit validation cap ({total} attempts) without a concrete candidate",
        )
    return (True, "")


def is_evidence_triggered_artifact_followup(
    todo: "PlannedTodo", state: "RunState", family: str
) -> bool:
    if family != "artifact-followup":
        return False
    context = todo.context or {}
    capability = str(
        DispatchIntent.from_context(context).required_capability or ""
    ).strip()
    if capability not in {
        "artifact.triage",
        "media.scan",
        "office.inspect",
        "png.inspect",
    }:
        return False
    if not has_context_path(context):
        return False
    return GroundingProjection(state).context_refs_existing(
        context, "evidence_id", "evidence_ids"
    )


def todo_family_candidates(todo: "PlannedTodo", family: str) -> set[str]:
    context = {**(todo.context or {}), "family": family}
    return family_candidates_for(
        todo.goal,
        context,
        [*todo.success_criteria, *todo.constraints],
    )


def forced_pivot_family_candidates(todo: "PlannedTodo", family: str) -> set[str]:
    context = {**(todo.context or {}), "family": family}
    return broad_family_candidates_for(
        todo.goal,
        context,
        [*todo.success_criteria, *todo.constraints],
    )
