"""Todo family counters used by progress gating and planner context."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from killchain_docker.orchestrator.progress.limits import (
    CONSECUTIVE_FAILURE_CAP,
    FAILURE_COOLDOWN_THRESHOLD,
)
from killchain_docker.orchestrator.todo.family import family_candidates_for, family_for
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.evidence_progress import evidence_ref_can_unlock_progress
from killchain_docker.state.todos import TodoItem, TodoStatus

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


_NON_TERMINAL_FAILURE_STATUSES = {
    TodoStatus.FAILED,
    TodoStatus.PARTIAL,
    TodoStatus.BLOCKED,
}


def todo_family(todo: TodoItem) -> str:
    return str(todo.context.get("family") or family_for(todo.goal, todo.context))


def todo_family_candidates(todo: TodoItem) -> set[str]:
    return family_candidates_for(
        todo.goal,
        todo.context,
        [*todo.success_criteria, *todo.constraints],
    )


def todo_yielded_progress_evidence(state: "RunState", todo: TodoItem) -> bool:
    """Return true when the todo's recorded evidence can unlock further progress.

    A PARTIAL/FAILED todo that produced an artifact, near-miss candidate, flag
    candidate, or non-no-progress observation has actually advanced the run.
    Counting it as a cooldown failure starves the planner of the only useful
    families, which is the most common run-killing pattern observed in batch
    logs (forced pivots banning the family that was making slow progress).
    """
    for evidence in state.evidence.values():
        if getattr(evidence, "task_id", None) != todo.todo_id:
            continue
        if evidence_ref_can_unlock_progress(state, evidence.evidence_id):
            return True
    return False


def family_counts(state: "RunState", family: str) -> tuple[int, int]:
    total = 0
    failed = 0
    for todo in TodoQueue(state).all():
        if family not in todo_family_candidates(todo):
            continue
        total += 1
        if todo.status not in _NON_TERMINAL_FAILURE_STATUSES:
            continue
        if todo.status == TodoStatus.PARTIAL and todo_yielded_progress_evidence(
            state, todo
        ):
            continue
        failed += 1
    return (total, failed)


def consecutive_failures_without_evidence(state: "RunState", family: str) -> int:
    family_todos = [
        todo
        for todo in TodoQueue(state).all()
        if family in todo_family_candidates(todo)
    ]
    consecutive = 0
    for todo in reversed(family_todos):
        if todo.status in _NON_TERMINAL_FAILURE_STATUSES:
            if todo.status == TodoStatus.PARTIAL and todo_yielded_progress_evidence(
                state, todo
            ):
                break
            consecutive += 1
        elif todo.status == TodoStatus.COMPLETED:
            if (
                todo.result_summary
                and "0 flag candidate" in todo.result_summary.lower()
                and not todo_yielded_progress_evidence(state, todo)
            ):
                consecutive += 1
            else:
                break
        else:
            continue
    return consecutive


def stagnation_snapshot(state: "RunState") -> dict[str, Any]:
    counts = Counter()
    failed_counts = Counter()
    for todo in TodoQueue(state).all():
        if todo.status in _NON_TERMINAL_FAILURE_STATUSES:
            productive = (
                todo.status == TodoStatus.PARTIAL
                and todo_yielded_progress_evidence(state, todo)
            )
        else:
            productive = False
        for family in todo_family_candidates(todo):
            counts[family] += 1
            if (
                todo.status in _NON_TERMINAL_FAILURE_STATUSES
                and not productive
            ):
                failed_counts[family] += 1
    return {
        "family_counts": dict(counts),
        "failed_or_partial_family_counts": dict(failed_counts),
        "cooldown_families": sorted(
            (
                family
                for family, count in failed_counts.items()
                if count >= FAILURE_COOLDOWN_THRESHOLD
            )
        ),
    }


def bankrupt_families(state: "RunState") -> list[tuple[str, int]]:
    bankrupt: list[tuple[str, int]] = []
    todos = TodoQueue(state).all()
    seen_families = {
        family for todo in todos for family in todo_family_candidates(todo)
    }
    for family in sorted(seen_families):
        consecutive = consecutive_failures_without_evidence(state, family)
        if consecutive >= CONSECUTIVE_FAILURE_CAP:
            bankrupt.append((family, consecutive))
    return bankrupt
