"""Todo dependency readiness and blocking policy."""

from __future__ import annotations
from collections.abc import Iterable
from killchain_docker.orchestrator.dispatch_types import (
    DependencyBlock,
    DependencyCheck,
    DependencyState,
)
from killchain_docker.orchestrator.todo_lifecycle import TodoLifecycle
from killchain_docker.orchestrator.todo_store import TodoStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoStatus


class TodoDependencyGate:
    """Resolves todo dependency references and blocks impossible work."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.store = TodoStore(state)
        self.lifecycle = TodoLifecycle(state)

    def check(self, todo: TodoItem) -> DependencyCheck:
        for ref in todo.depends_on:
            dependency = self.get_by_ref(ref)
            if dependency is None:
                return DependencyCheck(
                    DependencyState.UNSATISFIABLE, f"missing dependency {ref!r}"
                )
            if dependency.status in {TodoStatus.PENDING, TodoStatus.RUNNING}:
                return DependencyCheck(
                    DependencyState.WAITING, f"waiting for dependency {ref!r}"
                )
            if dependency.status not in {TodoStatus.COMPLETED, TodoStatus.PARTIAL}:
                return DependencyCheck(
                    DependencyState.UNSATISFIABLE,
                    f"dependency {ref!r} ended with status {dependency.status.value}",
                )
        return DependencyCheck(DependencyState.SATISFIED)

    def ready(self, todos: Iterable[TodoItem]) -> list[TodoItem]:
        return [todo for todo in todos if self.check(todo).satisfied]

    def blocked(self, todos: Iterable[TodoItem]) -> list[TodoItem]:
        return [todo for todo in todos if not self.check(todo).satisfied]

    def block_unsatisfiable(self, todos: Iterable[TodoItem]) -> list[DependencyBlock]:
        blocked: list[DependencyBlock] = []
        for todo in todos:
            check = self.check(todo)
            if not check.unsatisfiable:
                continue
            self.lifecycle.block(todo, check.reason, touch=False)
            blocked.append(DependencyBlock(todo, check.reason))
        if blocked:
            self.lifecycle.maintenance.touch()
        return blocked

    def get_by_ref(self, ref: str) -> TodoItem | None:
        return self.store.get_by_ref(ref)
