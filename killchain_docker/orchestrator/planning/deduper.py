"""Dedupe high-level planner todos."""

from __future__ import annotations

from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state import RunState


class TaskDeduper:
    """Assign stable dedupe keys and drop same-batch duplicates."""

    def merge(
        self,
        proposed: list[PlannedTodo],
        state: RunState,
        existing_keys: set[str] | None = None,
    ) -> list[PlannedTodo]:
        seen = set(existing_keys or set())
        seen.update(todo.dedupe_key for todo in state.todos if todo.dedupe_key)
        merged: list[PlannedTodo] = []
        for todo in proposed:
            candidate = todo.to_todo()
            if not todo.dedupe_key:
                todo.dedupe_key = state.default_todo_key(candidate)
            if todo.dedupe_key in seen:
                continue
            seen.add(todo.dedupe_key)
            merged.append(todo)
        return merged
