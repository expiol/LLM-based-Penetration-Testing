"""Shared dependency gating for planner-created todos."""

from __future__ import annotations

from collections.abc import Sequence

from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.run_state import RunState


def gate_planned_dependencies(
    todos: Sequence[PlannedTodo], state: RunState
) -> tuple[list[PlannedTodo], list[str]]:
    """Drop planner todos whose dependency refs cannot resolve after this batch."""

    queue = TodoQueue(state)
    proposed_refs = _proposed_refs(todos)
    kept: list[PlannedTodo] = []
    dropped_refs: list[str] = []
    for todo in todos:
        missing = [
            ref
            for ref in todo.depends_on
            if queue.get_by_ref(ref) is None and ref not in proposed_refs
        ]
        if missing:
            dropped_refs.extend(missing)
            continue
        kept.append(todo)
    if not dropped_refs:
        return (kept, [])
    return (
        kept,
        [
            "Planning dependency gate dropped "
            f"{len(todos) - len(kept)} todo(s) with missing dependency ref(s): "
            f"{sorted(set(dropped_refs))[:5]}."
        ],
    )


def _proposed_refs(todos: Sequence[PlannedTodo]) -> set[str]:
    refs: set[str] = set()
    for todo in todos:
        for value in (todo.dedupe_key, getattr(todo, "todo_id", None)):
            normalized = str(value or "").strip()
            if normalized:
                refs.add(normalized)
    return refs
