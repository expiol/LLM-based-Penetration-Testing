"""Write-side todo queue entrypoints."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch_types import EnqueueReport
from killchain_docker.orchestrator.todo_store import TodoStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem


class TodoQueueWriter:
    """Creates todos and reports planner enqueue outcomes."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.store = TodoStore(state)

    def enqueue(self, todo: TodoItem) -> TodoItem:
        return self.store.enqueue(todo, default_key=self.default_key)

    def enqueue_planned(self, planned_todos) -> EnqueueReport:
        proposed = 0
        created = 0
        created_ids: list[str] = []
        for planned_todo in planned_todos:
            proposed += 1
            todo = planned_todo.to_todo()
            queued = self.enqueue(todo)
            if queued.todo_id == todo.todo_id:
                created += 1
                created_ids.append(queued.todo_id)
        return EnqueueReport(
            proposed=proposed, created=created, created_ids=created_ids
        )

    @staticmethod
    def default_key(todo: TodoItem) -> str:
        from killchain_docker.orchestrator.todo_keys import default_key

        return default_key(todo)


__all__ = ["TodoQueueWriter"]
