"""Planner todo normalization pipeline."""

from __future__ import annotations
from typing import TYPE_CHECKING, Any
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.todo_artifact_references import (
    DurableArtifactReferenceNormalizer,
)
from killchain_docker.orchestrator.todo_artifact_targets import (
    TodoArtifactTargetNormalizer,
)
from killchain_docker.orchestrator.todo_family import (
    compound_disassembly_and_exploit,
    family_for,
    local_artifact_recovery,
)
from killchain_docker.orchestrator.actionable_tool_context import (
    apply_actionable_tool_context,
)
from killchain_docker.orchestrator.execution_closure_intent import (
    apply_execution_closure_context,
)
from killchain_docker.orchestrator.goal_predicates import goal_needs_files
from killchain_docker.orchestrator.todo_dispatch_intent import (
    finalize_dispatch_intent,
    set_required_capability,
)
from killchain_docker.orchestrator.todo_keys import default_key, structural_key
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.todos import TodoPhase

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state.run_state import RunState


def normalize_todo(todo: "PlannedTodo", state: "RunState") -> "PlannedTodo":
    context = todo.context
    projection = ChallengeProjection(state)
    challenge_files = projection.files()
    goal_l = todo.goal.lower()
    normalize_flag_format_context(context, projection.payload())
    DurableArtifactReferenceNormalizer.normalize(todo, state, context)
    family = family_for(todo.goal, context)
    family = TodoArtifactTargetNormalizer.normalize(
        todo, state, family, set_required_capability=set_required_capability
    )
    context["family"] = family
    if challenge_files and goal_needs_files(goal_l):
        context.setdefault("files_root", DEFAULT_FILES_ROOT)
        context.setdefault("challenge_files", challenge_files)
    apply_execution_closure_context(todo, context, family)
    candidate = CandidatePolicy.first_candidate_from_context(state, context, todo.goal)
    ready_candidates = CandidatePolicy.validation_ready_candidates(state)
    if candidate:
        context["candidate_flag"] = candidate
        todo.phase = TodoPhase.FLAG_VALIDATION
    elif todo.phase == TodoPhase.FLAG_VALIDATION and ready_candidates:
        context["candidate_flag"] = ready_candidates[0].value
        todo.phase = TodoPhase.FLAG_VALIDATION
    elif todo.phase == TodoPhase.FLAG_VALIDATION:
        todo.phase = TodoPhase.ANALYSIS
    if todo.phase == TodoPhase.EXPLOIT and local_artifact_recovery(
        goal_l, context, family
    ):
        todo.phase = TodoPhase.ANALYSIS
    if compound_disassembly_and_exploit(todo.goal):
        todo.phase = TodoPhase.ANALYSIS
        context["family"] = "binary-analysis"
        context["dispatch_intent"] = {
            "profile": "binary_analysis",
            "required_capability": "shell.exec",
        }
        todo.goal = "Extract precise binary algorithm evidence needed for the next decryption attempt."
        todo.success_criteria = [
            "Capture the exact algorithm or loop evidence needed for a later script."
        ]
    apply_actionable_tool_context(todo, context, family)
    finalize_dispatch_intent(context)
    key = structural_key(todo)
    if key:
        todo.dedupe_key = key
    elif not todo.dedupe_key:
        todo.dedupe_key = default_key(todo)
    return todo


def normalize_flag_format_context(
    context: dict[str, Any], challenge: dict[str, Any]
) -> None:
    expected_prefix = CandidatePolicy._expected_prefix(challenge.get("flag_format"))
    if expected_prefix:
        context["flag_format_prefix"] = f"{expected_prefix}{{"
        return
    context.pop("flag_format_prefix", None)
