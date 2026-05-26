"""Todo lifecycle transitions backed by ``RunState.todos``."""

from __future__ import annotations
from killchain_docker.orchestrator.todo_store import TodoStore
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.common import utc_now
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoStatus


class TodoLifecycle:
    """Owns every status mutation for queued todos."""

    def __init__(self, state: RunState) -> None:
        self.state = state
        self.store = TodoStore(state)
        self.maintenance = RunStateMaintenance(state)

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
        self, todo: TodoItem, error: str, *, retryable: bool, touch: bool = True
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
        todo.status = TodoStatus.BLOCKED
        todo.error = reason
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def interrupt(self, todo: TodoItem, reason: str, *, touch: bool = True) -> None:
        todo.status = TodoStatus.INTERRUPTED
        todo.error = reason
        todo.updated_at = utc_now()
        if touch:
            self.maintenance.touch()

    def apply_result(self, todo: TodoItem, result, *, touch: bool = True) -> None:
        if result.partial:
            self.partial(
                todo, result.summary, result.partial_reason or result.error, touch=False
            )
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

    def interrupt_running(self, reason: str) -> int:
        interrupted = 0
        for todo in self.store.running():
            self.interrupt(todo, reason, touch=False)
            interrupted += 1
        if interrupted:
            self.maintenance.touch()
        return interrupted

    def fail_running(self, reason: str, *, retryable: bool = False) -> int:
        failed = 0
        for todo in self.store.running():
            self.fail(todo, reason, retryable=retryable, touch=False)
            failed += 1
        if failed:
            self.maintenance.touch()
        return failed

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

    def block_open(self, reason: str) -> int:
        blocked = 0
        for todo in self.store.open():
            self.block(todo, reason, touch=False)
            blocked += 1
        if blocked:
            self.maintenance.touch()
        return blocked
