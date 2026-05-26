"""Test helper for the split todo queue APIs."""

from __future__ import annotations

from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.orchestrator.todo_queue_writer import TodoQueueWriter
from killchain_docker.orchestrator.todo_status_commands import TodoStatusCommands
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem


class TodoQueueHarness:
    def __init__(self, state: RunState) -> None:
        self.reader = TodoQueueReader(state)
        self.writer = TodoQueueWriter(state)
        self.commands = TodoStatusCommands(state)

    def enqueue(self, todo: TodoItem) -> TodoItem:
        return self.writer.enqueue(todo)

    def enqueue_planned(self, planned_todos):
        return self.writer.enqueue_planned(planned_todos)

    def __getattr__(self, name: str):
        if hasattr(self.reader, name):
            return getattr(self.reader, name)
        return getattr(self.commands, name)


def todo_queue(state: RunState) -> TodoQueueHarness:
    return TodoQueueHarness(state)


__all__ = ["TodoQueueHarness", "todo_queue"]
