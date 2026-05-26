"""Ready todo batch selection for routing."""

from __future__ import annotations

from killchain_docker.orchestrator.dispatch_types import QueuedTodoBatch
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.todos import todo_phase_rank


class DispatchScheduler:
    """Selects the next coherent batch of ready todos."""

    def __init__(self, *, max_assignments: int) -> None:
        self.max_assignments = max(1, max_assignments)

    def next_batch(self, queue: TodoQueueReader) -> QueuedTodoBatch:
        ready = queue.ready(limit=None)
        if not ready:
            return QueuedTodoBatch(
                todos=[],
                focus_phase=None,
                blocked_by_dependency=queue.blocked_by_dependency(),
            )
        focus_phase = min((todo.phase for todo in ready), key=todo_phase_rank)
        todos = [todo for todo in ready if todo.phase == focus_phase][
            : self.max_assignments
        ]
        return QueuedTodoBatch(
            todos=todos,
            focus_phase=focus_phase,
            blocked_by_dependency=queue.blocked_by_dependency(),
        )
