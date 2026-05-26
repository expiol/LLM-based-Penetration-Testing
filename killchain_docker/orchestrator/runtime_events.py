"""Runtime event emission and checkpoint callbacks."""

from __future__ import annotations
from collections.abc import Callable, Iterable
from inspect import Parameter, signature
import killchain_docker.orchestrator.background_flags as background_flags
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.domain import FlagCandidate
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem

EmitEvent = Callable[..., None]


def _supports_structured_emit(callback: Callable[..., object]) -> bool:
    try:
        parameters = signature(callback).parameters.values()
    except (TypeError, ValueError):
        return False
    names = {parameter.name for parameter in parameters}
    has_context = any(
        (parameter.kind == Parameter.VAR_KEYWORD for parameter in parameters)
    )
    return "event_type" in names and has_context


class RuntimeEventController:
    """Owns runtime event emission, checkpoints, and worker callbacks."""

    def __init__(
        self,
        *,
        state: RunState,
        emit: EmitEvent,
        checkpoint: Callable[[], None],
        background_flags: background_flags.BackgroundFlagValidationController
        | None = None,
    ) -> None:
        self.state = state
        self._emit = emit
        self._structured_emit = _supports_structured_emit(emit)
        self._checkpoint = checkpoint
        self._background_flags = background_flags

    def emit(
        self, message: str, *, event_type: str | None = None, **context: object
    ) -> None:
        if self._structured_emit:
            self._emit(message, event_type=event_type, **context)
            return
        self._emit(message)

    def checkpoint_activity(self, message: str, **context: object) -> None:
        self.emit(message, **context)
        RunStateMaintenance(self.state).touch()
        self._checkpoint()

    def checkpoint(self) -> None:
        self._checkpoint()

    def todo_context(
        self, cycle: int, todo: TodoItem, *, worker: str | None = None
    ) -> dict[str, object]:
        return {
            "cycle": cycle,
            "todo_id": todo.todo_id,
            "todo_status": str(todo.status),
            "todo_phase": str(todo.phase),
            "worker": worker or todo.assigned_worker,
        }

    def worker_progress(
        self, cycle: int, state: RunState, todo: TodoItem, message: str
    ) -> None:
        self.emit(
            f"[cycle {cycle}] {todo.todo_id}: {message}",
            event_type="worker_progress",
            **self.todo_context(cycle, todo),
        )
        RunStateMaintenance(state).touch()
        self._checkpoint()
        if self.sync_background_flags(cycle):
            raise background_flags.BackgroundFlagSolved()

    def worker_flag_candidates(
        self,
        cycle: int,
        state: RunState,
        todo: TodoItem,
        candidates: Iterable[FlagCandidate],
    ) -> None:
        candidate_list = list(candidates)
        if not candidate_list:
            return
        queued = 0
        if self._background_flags is not None:
            queued = self._background_flags.enqueue_candidates(candidate_list)
        if queued:
            self.emit(
                f"[cycle {cycle}] queued {queued} flag candidate(s) for background validation",
                event_type="flag_candidate_queued",
                **self.todo_context(cycle, todo),
            )
        RunStateMaintenance(state).touch()
        self._checkpoint()
        if self.sync_background_flags(cycle, wait_s=0.05):
            raise background_flags.BackgroundFlagSolved()

    def sync_background_flags(self, cycle: int, *, wait_s: float = 0.0) -> bool:
        if self._background_flags is None:
            return False
        return self._background_flags.sync(cycle, wait_s=wait_s)
