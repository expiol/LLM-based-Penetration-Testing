"""Single source of truth for ``RunState.todos`` reads, writes, and status transitions.

Every mutation of the todo queue happens through this module. The interface is
what callers actually use — there are no separate read/write/status facades.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from killchain_docker.orchestrator.dispatch.types import (
    DependencyBlock,
    DependencyCheck,
    DependencyState,
    EnqueueReport,
)
from killchain_docker.orchestrator.todo.keys import default_key
from killchain_docker.state.common import utc_now
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
_TERMINAL_UNSOLVED_STATUSES = {
    TodoStatus.FAILED,
    TodoStatus.BLOCKED,
    TodoStatus.PARTIAL,
}


class TodoQueue:
    """Reads, writes, and status transitions over ``RunState.todos``."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    # ------------------------------------------------------------------ reads

    def all(self) -> list[TodoItem]:
        return list(self.state.todos)

    def count(self) -> int:
        return len(self.state.todos)

    def empty(self) -> bool:
        return not self.state.todos

    def pending_sorted(self) -> list[TodoItem]:
        ready = [
            todo for todo in self.state.todos if todo.status == TodoStatus.PENDING
        ]
        ready.sort(key=lambda item: (-item.priority, item.created_at))
        return ready

    def running(self) -> list[TodoItem]:
        return [todo for todo in self.state.todos if todo.status == TodoStatus.RUNNING]

    def open(self) -> list[TodoItem]:
        return [todo for todo in self.state.todos if todo.status in _OPEN_STATUSES]

    def has_open(self) -> bool:
        return any(todo.status in _OPEN_STATUSES for todo in self.state.todos)

    def open_count(self) -> int:
        return sum(1 for todo in self.state.todos if todo.status in _OPEN_STATUSES)

    def open_phases(self) -> list[TodoPhase]:
        return [
            todo.phase for todo in self.state.todos if todo.status in _OPEN_STATUSES
        ]

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
        return any(todo.dedupe_key == dedupe_key for todo in self.state.todos)

    def dedupe_keys(self) -> set[str]:
        return {todo.dedupe_key for todo in self.state.todos if todo.dedupe_key}

    def completed_dedupe_key(self, dedupe_key: str) -> bool:
        return any(
            todo.dedupe_key == dedupe_key and todo.status == TodoStatus.COMPLETED
            for todo in self.state.todos
        )

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

    def atomic_recon_keys(self, families: set[str]) -> set[tuple[str, str]]:
        keys: set[tuple[str, str]] = set()
        for todo in self.state.todos:
            family = str(todo.context.get("family") or "")
            if family in families and todo.phase == TodoPhase.RECON:
                keys.add((family, str(todo.context.get("files_root") or "")))
        return keys

    def active_validation_candidates(
        self, candidate_for: Callable[[TodoItem], str]
    ) -> set[str]:
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
        return any(predicate(todo) for todo in self.state.todos)

    def has_terminal_unsolved(self) -> bool:
        return any(
            todo.status in _TERMINAL_UNSOLVED_STATUSES for todo in self.state.todos
        )

    def terminal_unsolved_reason(self) -> str:
        todos = self.state.todos
        if any(todo.status == TodoStatus.FAILED for todo in todos):
            return "todo_failed"
        if any(todo.status == TodoStatus.BLOCKED for todo in todos):
            return "todo_blocked"
        if any(todo.status == TodoStatus.PARTIAL for todo in todos):
            return "partial_todos_unsolved"
        if todos:
            return "unsolved_no_work_remaining"
        return "no_todos_created"

    # ------------------------------------------------------------ dependency

    def dependency_check(self, todo: TodoItem) -> DependencyCheck:
        for ref in todo.depends_on:
            dependency = self.get_by_ref(ref)
            if dependency is None:
                return DependencyCheck(
                    DependencyState.UNSATISFIABLE, f"missing dependency {ref!r}"
                )
            if dependency.status in _OPEN_STATUSES:
                return DependencyCheck(
                    DependencyState.WAITING, f"waiting for dependency {ref!r}"
                )
            if dependency.status not in {TodoStatus.COMPLETED, TodoStatus.PARTIAL}:
                return DependencyCheck(
                    DependencyState.UNSATISFIABLE,
                    f"dependency {ref!r} ended with status {dependency.status.value}",
                )
        return DependencyCheck(DependencyState.SATISFIED)

    def ready(self, *, limit: int | None = None) -> list[TodoItem]:
        ready = [
            todo
            for todo in self.pending_sorted()
            if self.dependency_check(todo).satisfied
        ]
        return ready[:limit] if limit is not None else ready

    def has_ready(self) -> bool:
        return bool(self.ready(limit=1))

    def blocked_by_dependency(self) -> list[TodoItem]:
        return [
            todo
            for todo in self.pending_sorted()
            if not self.dependency_check(todo).satisfied
        ]

    def block_unsatisfiable_dependencies(self) -> list[DependencyBlock]:
        blocked: list[DependencyBlock] = []
        for todo in self.pending_sorted():
            check = self.dependency_check(todo)
            if not check.unsatisfiable:
                continue
            self._block(todo, check.reason, touch=False)
            blocked.append(DependencyBlock(todo, check.reason))
        if blocked:
            self.maintenance.touch()
        return blocked

    # ------------------------------------------------------------------ writes

    def enqueue(self, todo: TodoItem) -> TodoItem:
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

    def enqueue_planned(self, planned_todos: Iterable[object]) -> EnqueueReport:
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

    # ------------------------------------------------------------ status mutations

    def start(self, todo: TodoItem, worker_name: str, *, touch: bool = True) -> None:
        todo.status = TodoStatus.RUNNING
        todo.assigned_worker = worker_name
        todo.attempts += 1
        todo.error = None
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def complete(self, todo: TodoItem, summary: str, *, touch: bool = True) -> None:
        todo.status = TodoStatus.COMPLETED
        todo.result_summary = summary
        todo.error = None
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def partial(
        self,
        todo: TodoItem,
        summary: str,
        reason: str | None = None,
        *,
        touch: bool = True,
    ) -> None:
        todo.status = TodoStatus.PARTIAL
        todo.result_summary = summary
        todo.error = reason
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def fail(
        self,
        todo: TodoItem,
        error: str,
        *,
        retryable: bool,
        touch: bool = True,
    ) -> None:
        todo.error = error
        if retryable and todo.attempts < todo.max_attempts:
            todo.status = TodoStatus.PENDING
        else:
            todo.status = TodoStatus.FAILED
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def release_transient(
        self, todo: TodoItem, reason: str, *, touch: bool = True
    ) -> None:
        del reason
        if todo.status == TodoStatus.RUNNING:
            todo.status = TodoStatus.PENDING
            if todo.attempts > 0:
                todo.attempts -= 1
        todo.error = None
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def block(self, todo: TodoItem, reason: str, *, touch: bool = True) -> None:
        self._block(todo, reason, touch=touch)

    def interrupt(self, todo: TodoItem, reason: str, *, touch: bool = True) -> None:
        todo.status = TodoStatus.INTERRUPTED
        todo.error = reason
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def apply_result(self, todo: TodoItem, result, *, touch: bool = True) -> None:
        if result.partial:
            partial_reason = result.partial_reason or result.error
            if todo.attempts < todo.max_attempts:
                todo.status = TodoStatus.PENDING
                todo.result_summary = result.summary
                todo.error = partial_reason
                todo.assigned_worker = None
                todo.updated_at = utc_now()
            else:
                self.partial(todo, result.summary, partial_reason, touch=False)
        elif result.success:
            self.complete(todo, result.summary, touch=False)
        else:
            self.fail(
                todo,
                result.error or result.summary,
                retryable=result.retryable,
                touch=False,
            )
        if touch:
            self.maintenance.touch()

    # --------------------------------------------------------- bulk mutations

    def interrupt_running(self, reason: str) -> int:
        interrupted = 0
        for todo in self.running():
            self.interrupt(todo, reason, touch=False)
            interrupted += 1
        if interrupted:
            self.maintenance.touch()
        return interrupted

    def fail_running(self, reason: str, *, retryable: bool = False) -> int:
        failed = 0
        for todo in self.running():
            self.fail(todo, reason, retryable=retryable, touch=False)
            failed += 1
        if failed:
            self.maintenance.touch()
        return failed

    def block_open(self, reason: str) -> int:
        blocked = 0
        for todo in self.open():
            self._block(todo, reason, touch=False)
            blocked += 1
        if blocked:
            self.maintenance.touch()
        return blocked

    def halt_for_transient_error(
        self, reason: str, *, todo: TodoItem | None = None
    ) -> int:
        if todo is None:
            return self.interrupt_running(reason)
        changed = 0
        if todo.status == TodoStatus.RUNNING:
            self.release_transient(todo, reason, touch=False)
        if todo.status == TodoStatus.PENDING:
            self.interrupt(todo, reason, touch=False)
            changed += 1
        if changed:
            self.maintenance.touch()
        return changed

    # --------------------------------------------------------------- private

    def _block(self, todo: TodoItem, reason: str, *, touch: bool) -> None:
        todo.status = TodoStatus.BLOCKED
        todo.error = reason
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()


__all__ = ["TodoQueue"]
