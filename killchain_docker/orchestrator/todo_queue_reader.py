"""Read-side todo queue views for planning and dispatch."""

from __future__ import annotations

from collections.abc import Callable

from killchain_docker.orchestrator.dispatch_types import DependencyCheck
from killchain_docker.orchestrator.todo_dependencies import TodoDependencyGate
from killchain_docker.orchestrator.todo_store import TodoStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, TodoStatus


class TodoQueueReader:
    """Read-only todo queue model backed by RunState."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.store = TodoStore(state)
        self.dependencies = TodoDependencyGate(state)

    def ready(self, *, limit: int | None = None) -> list[TodoItem]:
        ready = self.dependencies.ready(self.store.pending_sorted())
        return ready[:limit] if limit is not None else ready

    def blocked_by_dependency(self) -> list[TodoItem]:
        return self.dependencies.blocked(self.store.pending_sorted())

    def has_ready(self) -> bool:
        return bool(self.ready(limit=1))

    def has_open(self) -> bool:
        return self.store.has_open()

    def open_count(self) -> int:
        return self.store.open_count()

    def count(self) -> int:
        return self.store.count()

    def recent(self, *, limit: int) -> list[TodoItem]:
        return self.store.recent(limit=limit)

    def all(self) -> list[TodoItem]:
        return self.store.all()

    def recent_by_status(
        self, statuses: set[TodoStatus], *, limit: int
    ) -> list[TodoItem]:
        return self.store.recent_by_status(statuses, limit=limit)

    def family_counts(self, family_for: Callable[[TodoItem], str]) -> dict[str, int]:
        return self.store.family_counts(family_for)

    def family_examples(
        self, family_for: Callable[[TodoItem], str], *, per_family: int
    ) -> dict[str, list[str]]:
        return self.store.family_examples(family_for, per_family=per_family)

    def families(self, family_for: Callable[[TodoItem], str]) -> list[str]:
        return self.store.families(family_for)

    def by_family(
        self, family: str, family_for: Callable[[TodoItem], str]
    ) -> list[TodoItem]:
        return self.store.by_family(family, family_for)

    def get(self, todo_id: str) -> TodoItem | None:
        return self.store.get(todo_id)

    def get_by_ref(self, ref: str) -> TodoItem | None:
        return self.dependencies.get_by_ref(ref)

    def has_dedupe_key(self, dedupe_key: str) -> bool:
        return self.store.has_dedupe_key(dedupe_key)

    def empty(self) -> bool:
        return self.store.empty()

    def completed_dedupe_key(self, dedupe_key: str) -> bool:
        return self.store.completed_dedupe_key(dedupe_key)

    def dedupe_keys(self) -> set[str]:
        return self.store.dedupe_keys()

    def open_phases(self) -> list[TodoPhase]:
        return self.store.open_phases()

    def atomic_recon_keys(self, families: set[str]) -> set[tuple[str, str]]:
        return self.store.atomic_recon_keys(families)

    def active_validation_candidates(self, candidate_for) -> set[str]:
        return self.store.active_validation_candidates(candidate_for)

    def has_context_path(self, predicate: Callable[[TodoItem], bool]) -> bool:
        return self.store.has_context_path(predicate)

    def dependency_check(self, todo: TodoItem) -> DependencyCheck:
        return self.dependencies.check(todo)

    def has_terminal_unsolved(self) -> bool:
        return bool(TodoStore.terminal_unsolved(self.store.all()))

    def terminal_unsolved_reason(self) -> str:
        todo_list = self.store.all()
        if any((todo.status == TodoStatus.FAILED for todo in todo_list)):
            return "todo_failed"
        if any((todo.status == TodoStatus.BLOCKED for todo in todo_list)):
            return "todo_blocked"
        if any((todo.status == TodoStatus.PARTIAL for todo in todo_list)):
            return "partial_todos_unsolved"
        if todo_list:
            return "unsolved_no_work_remaining"
        return "no_todos_created"


__all__ = ["TodoQueueReader"]
