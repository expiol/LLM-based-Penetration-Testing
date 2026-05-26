"""Todo family counters used by progress gating and planner context."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from killchain_docker.orchestrator.progress_limits import (
    CONSECUTIVE_FAILURE_CAP,
    FAILURE_COOLDOWN_THRESHOLD,
)
from killchain_docker.orchestrator.todo_family import family_for
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.todos import TodoItem, TodoStatus

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


def todo_family(todo: TodoItem) -> str:
    return str(todo.context.get("family") or family_for(todo.goal, todo.context))


def family_counts(state: "RunState", family: str) -> tuple[int, int]:
    total = 0
    failed = 0
    for todo in TodoQueueReader(state).by_family(family, todo_family):
        total += 1
        if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
            failed += 1
    return (total, failed)


def consecutive_failures_without_evidence(state: "RunState", family: str) -> int:
    family_todos = TodoQueueReader(state).by_family(family, todo_family)
    consecutive = 0
    for todo in reversed(family_todos):
        if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
            consecutive += 1
        elif todo.status == TodoStatus.COMPLETED:
            if (
                todo.result_summary
                and "0 flag candidate" in todo.result_summary.lower()
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
    queue = TodoQueueReader(state)
    for family in queue.families(todo_family):
        family_todos = queue.by_family(family, todo_family)
        counts[family] += len(family_todos)
        failed_counts[family] += sum(
            (
                1
                for todo in family_todos
                if todo.status
                in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}
            )
        )
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
    queue = TodoQueueReader(state)
    bankrupt: list[tuple[str, int]] = []
    for family in queue.families(todo_family):
        consecutive = consecutive_failures_without_evidence(state, family)
        if consecutive >= CONSECUTIVE_FAILURE_CAP:
            bankrupt.append((family, consecutive))
    return bankrupt
