"""Flag validation policy shared by flag-worker and background validation."""

from __future__ import annotations
import re
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.state.domain import FlagCandidate, StateDelta
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.core import _strings


def flag_validation_result(
    task: TodoItem, state: RunState, *, worker_name: str, expected_flag: str | None
) -> WorkerResult | None:
    """Validate ready candidates for the dedicated flag-worker path."""
    candidates = [
        candidate
        for candidate in _strings(task.context.get("candidate_flag"))
        if CandidatePolicy.accepts_for_state(state, candidate)
    ]
    if not candidates:
        candidates = [
            candidate.value
            for candidate in CandidatePolicy.validation_ready_candidates(state)
        ]
    if not candidates:
        return None
    expected = str(expected_flag or "").strip()
    if not expected:
        return None
    for candidate in candidates:
        if flag_matches(candidate, expected):
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=worker_name,
                success=True,
                summary=f"Validated flag candidate {candidate}.",
                state_delta=StateDelta(
                    flag_candidates=[
                        FlagCandidate(
                            value=candidate,
                            source="flag-validation",
                            confidence=1.0,
                            validated=True,
                        )
                    ]
                ),
                solved=True,
                validated_flag=expected,
                notes=[f"{worker_name} validated the final flag."],
            )
    return WorkerResult(
        todo_id=task.todo_id,
        worker_name=worker_name,
        success=False,
        summary="Flag candidates were tested but did not match the expected flag.",
        state_delta=StateDelta(
            flag_candidates=[
                FlagCandidate(
                    value=candidate,
                    source="flag-validation",
                    confidence=0.1,
                    validated=False,
                    rejected_reason="candidate mismatch",
                )
                for candidate in candidates
            ]
        ),
        error="candidate mismatch",
        retryable=False,
    )


def flag_matches(candidate: str, expected: str) -> bool:
    candidate_text = candidate.strip()
    expected_text = expected.strip()
    if candidate_text == expected_text:
        return True
    candidate_inner = unwrap_flag(candidate_text)
    expected_inner = unwrap_flag(expected_text)
    if candidate_inner == expected_inner:
        return True
    if prefix := flag_prefix(expected_text):
        if f"{prefix}{{{candidate_text}}}" == expected_text:
            return True
    return candidate_inner.lower() == expected_inner.lower()


def unwrap_flag(value: str) -> str:
    match = re.match("[A-Za-z0-9_]+\\{(.+)\\}\\s*$", value, re.DOTALL)
    return match.group(1) if match else value


def flag_prefix(value: str) -> str | None:
    match = re.match("([A-Za-z0-9_]+)\\{", value)
    return match.group(1) if match else None
