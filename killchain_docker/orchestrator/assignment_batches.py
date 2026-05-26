"""Batch routed assignments by tool execution safety."""

from __future__ import annotations

from dataclasses import dataclass

from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoItem, WorkerAssignment
from killchain_docker.tools.capabilities import ToolCapability, tool_spec


@dataclass(frozen=True)
class AssignmentExecutionBatch:
    assignments: list[WorkerAssignment]
    concurrent: bool = False


def assignment_execution_batches(
    assignments: list[WorkerAssignment],
    todos_by_id: dict[str, TodoItem],
) -> list[AssignmentExecutionBatch]:
    batches: list[AssignmentExecutionBatch] = []
    current_safe: list[WorkerAssignment] = []
    current_workers: set[str] = set()
    for assignment in assignments:
        todo = todos_by_id.get(assignment.todo_id)
        if (
            todo is not None
            and assignment_is_concurrency_safe(todo)
            and assignment.worker_name not in current_workers
        ):
            current_safe.append(assignment)
            current_workers.add(assignment.worker_name)
            continue
        if current_safe:
            batches.append(
                AssignmentExecutionBatch(assignments=current_safe, concurrent=True)
            )
            current_safe = []
            current_workers = set()
        if todo is not None and assignment_is_concurrency_safe(todo):
            current_safe.append(assignment)
            current_workers.add(assignment.worker_name)
            continue
        batches.append(
            AssignmentExecutionBatch(assignments=[assignment], concurrent=False)
        )
    if current_safe:
        batches.append(
            AssignmentExecutionBatch(assignments=current_safe, concurrent=True)
        )
    return batches


def assignment_is_concurrency_safe(todo: TodoItem) -> bool:
    capability = _required_capability(todo)
    if capability is None:
        return False
    spec = tool_spec(capability)
    return bool(
        spec
        and spec.direct
        and spec.read_only
        and spec.concurrency_safe
        and not spec.destructive
    )


def _required_capability(todo: TodoItem) -> ToolCapability | None:
    raw = str(
        DispatchIntent.from_context(todo.context).required_capability or ""
    ).strip()
    if not raw:
        return None
    try:
        return ToolCapability(raw)
    except ValueError:
        return None
