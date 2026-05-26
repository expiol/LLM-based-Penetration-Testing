"""Persistent todo storage and query helpers."""

from __future__ import annotations
from collections.abc import Callable, Iterable
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, TodoStatus

_DEDUPED_STATUSES = {
    TodoStatus.PENDING,
    TodoStatus.RUNNING,
    TodoStatus.COMPLETED,
    TodoStatus.PARTIAL,
}
_OPEN_STATUSES = {TodoStatus.PENDING, TodoStatus.RUNNING}


class TodoStore:
    """Owns raw ``RunState.todos`` access for the orchestrator."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def enqueue(
        self, todo: TodoItem, *, default_key: Callable[[TodoItem], str]
    ) -> TodoItem:
        if not todo.dedupe_key:
            todo.dedupe_key = default_key(todo)
        existing = next(
            (
                item
                for item in self.state.todos
                if item.dedupe_key == todo.dedupe_key
                and item.status in _DEDUPED_STATUSES
            ),
            None,
        )
        if existing is not None:
            self.maintenance.touch()
            return existing
        self.state.todos.append(todo)
        self.maintenance.touch()
        return todo

    def all(self) -> list[TodoItem]:
        return list(self.state.todos)

    def pending_sorted(self) -> list[TodoItem]:
        ready = [todo for todo in self.state.todos if todo.status == TodoStatus.PENDING]
        ready.sort(key=lambda item: (-item.priority, item.created_at))
        return ready

    def running(self) -> list[TodoItem]:
        return [todo for todo in self.state.todos if todo.status == TodoStatus.RUNNING]

    def open(self) -> list[TodoItem]:
        return [todo for todo in self.state.todos if todo.status in _OPEN_STATUSES]

    def has_open(self) -> bool:
        return any((todo.status in _OPEN_STATUSES for todo in self.state.todos))

    def open_count(self) -> int:
        return sum((1 for todo in self.state.todos if todo.status in _OPEN_STATUSES))

    def count(self) -> int:
        return len(self.state.todos)

    def recent(self, *, limit: int) -> list[TodoItem]:
        if limit <= 0:
            return []
        return list(self.state.todos[-limit:])

    def recent_by_status(
        self, statuses: set[TodoStatus], *, limit: int
    ) -> list[TodoItem]:
        if limit <= 0:
            return []
        return [todo for todo in self.state.todos[-limit:] if todo.status in statuses]

    def family_counts(self, family_for: Callable[[TodoItem], str]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for todo in self.state.todos:
            family = family_for(todo)
            counts[family] = counts.get(family, 0) + 1
        return counts

    def family_examples(
        self, family_for: Callable[[TodoItem], str], *, per_family: int
    ) -> dict[str, list[str]]:
        examples: dict[str, list[str]] = {}
        for todo in self.state.todos:
            family = family_for(todo)
            examples.setdefault(family, [])
            if len(examples[family]) < per_family:
                examples[family].append(todo.goal[:120])
        return examples

    def families(self, family_for: Callable[[TodoItem], str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for todo in self.state.todos:
            family = family_for(todo)
            if family in seen:
                continue
            seen.add(family)
            out.append(family)
        return out

    def by_family(
        self, family: str, family_for: Callable[[TodoItem], str]
    ) -> list[TodoItem]:
        return [todo for todo in self.state.todos if family_for(todo) == family]

    def get(self, todo_id: str) -> TodoItem | None:
        return next(
            (todo for todo in self.state.todos if todo.todo_id == todo_id), None
        )

    def get_by_ref(self, ref: str) -> TodoItem | None:
        normalized = str(ref or "").strip()
        if not normalized:
            return None
        return next(
            (
                todo
                for todo in self.state.todos
                if todo.todo_id == normalized or todo.dedupe_key == normalized
            ),
            None,
        )

    def has_dedupe_key(self, dedupe_key: str) -> bool:
        return any((todo.dedupe_key == dedupe_key for todo in self.state.todos))

    def empty(self) -> bool:
        return not self.state.todos

    def completed_dedupe_key(self, dedupe_key: str) -> bool:
        return any(
            (
                todo.dedupe_key == dedupe_key and todo.status == TodoStatus.COMPLETED
                for todo in self.state.todos
            )
        )

    def dedupe_keys(self) -> set[str]:
        return {todo.dedupe_key for todo in self.state.todos if todo.dedupe_key}

    def open_phases(self) -> list[TodoPhase]:
        return [
            todo.phase for todo in self.state.todos if todo.status in _OPEN_STATUSES
        ]

    def atomic_recon_keys(self, families: set[str]) -> set[tuple[str, str]]:
        keys: set[tuple[str, str]] = set()
        for todo in self.state.todos:
            family = str(todo.context.get("family") or "")
            if family in families and todo.phase == TodoPhase.RECON:
                keys.add((family, str(todo.context.get("files_root") or "")))
        return keys

    def active_validation_candidates(self, candidate_for) -> set[str]:
        candidates: set[str] = set()
        for todo in self.state.todos:
            if todo.phase != TodoPhase.FLAG_VALIDATION:
                continue
            if todo.status not in _DEDUPED_STATUSES:
                continue
            candidate = candidate_for(todo)
            if candidate:
                candidates.add(candidate)
        return candidates

    def has_context_path(self, predicate: Callable[[TodoItem], bool]) -> bool:
        return any((predicate(todo) for todo in self.state.todos))

    @staticmethod
    def terminal_unsolved(todos: Iterable[TodoItem]) -> list[TodoItem]:
        return [
            todo
            for todo in todos
            if todo.status
            in {TodoStatus.FAILED, TodoStatus.BLOCKED, TodoStatus.PARTIAL}
        ]
