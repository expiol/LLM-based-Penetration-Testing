"""Status-changing todo queue commands."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch_types import DependencyBlock
from killchain_docker.orchestrator.todo_dependencies import TodoDependencyGate
from killchain_docker.orchestrator.todo_lifecycle import TodoLifecycle
from killchain_docker.orchestrator.todo_store import TodoStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem


class TodoStatusCommands:
    """All todo status mutations used by runtime execution."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.store = TodoStore(state)
        self.dependencies = TodoDependencyGate(state)
        self.lifecycle = TodoLifecycle(state)

    def block_unsatisfiable_dependencies(self) -> list[DependencyBlock]:
        return self.dependencies.block_unsatisfiable(self.store.pending_sorted())

    def interrupt_running(self, reason: str) -> int:
        return self.lifecycle.interrupt_running(reason)

    def fail_running(self, reason: str, *, retryable: bool = False) -> int:
        return self.lifecycle.fail_running(reason, retryable=retryable)

    def halt_for_transient_error(
        self, reason: str, *, todo: TodoItem | None = None
    ) -> int:
        return self.lifecycle.halt_for_transient_error(reason, todo=todo)

    def block_open(self, reason: str) -> int:
        return self.lifecycle.block_open(reason)

    def start(self, todo: TodoItem, worker_name: str, *, touch: bool = True) -> None:
        self.lifecycle.start(todo, worker_name, touch=touch)

    def complete(self, todo: TodoItem, summary: str, *, touch: bool = True) -> None:
        self.lifecycle.complete(todo, summary, touch=touch)

    def partial(
        self,
        todo: TodoItem,
        summary: str,
        reason: str | None = None,
        *,
        touch: bool = True,
    ) -> None:
        self.lifecycle.partial(todo, summary, reason, touch=touch)

    def fail(
        self, todo: TodoItem, error: str, *, retryable: bool, touch: bool = True
    ) -> None:
        self.lifecycle.fail(todo, error, retryable=retryable, touch=touch)

    def release_transient(
        self, todo: TodoItem, reason: str, *, touch: bool = True
    ) -> None:
        self.lifecycle.release_transient(todo, reason, touch=touch)

    def block(self, todo: TodoItem, reason: str, *, touch: bool = True) -> None:
        self.lifecycle.block(todo, reason, touch=touch)

    def interrupt(self, todo: TodoItem, reason: str, *, touch: bool = True) -> None:
        self.lifecycle.interrupt(todo, reason, touch=touch)

    def apply_result(self, todo: TodoItem, result, *, touch: bool = True) -> None:
        self.lifecycle.apply_result(todo, result, touch=touch)


__all__ = ["TodoStatusCommands"]
