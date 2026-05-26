"""Runtime task state and assignment lifecycle coordination."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from killchain_docker.orchestrator.agent_lifecycle import AgentLifecycle
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.common import utc_now
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.workers.runtime.agent import WorkerAgent


class RuntimeTaskType(StrEnum):
    WORKER_ASSIGNMENT = "worker_assignment"
    TOOL_EXECUTION = "tool_execution"
    BACKGROUND_VALIDATOR = "background_validator"


class RuntimeTaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


TERMINAL_RUNTIME_TASK_STATUSES = {
    RuntimeTaskStatus.COMPLETED,
    RuntimeTaskStatus.FAILED,
    RuntimeTaskStatus.INTERRUPTED,
}


def is_terminal_runtime_task_status(status: RuntimeTaskStatus | str) -> bool:
    return RuntimeTaskStatus(status) in TERMINAL_RUNTIME_TASK_STATUSES


@dataclass
class RuntimeTaskState:
    """Small lifecycle record for one runtime action."""

    task_id: str
    type: RuntimeTaskType
    description: str
    status: RuntimeTaskStatus = RuntimeTaskStatus.PENDING
    worker_name: str | None = None
    todo_id: str | None = None
    error: str | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None
    updated_at: datetime = field(default_factory=utc_now)


class RuntimeTaskRegistry:
    """In-memory runtime task plane."""

    def __init__(self) -> None:
        self._tasks: dict[str, RuntimeTaskState] = {}

    def register(self, task: RuntimeTaskState) -> RuntimeTaskState:
        self._tasks[task.task_id] = task
        return task

    def start(self, task_id: str) -> None:
        task = self._tasks[task_id]
        started_at = utc_now()
        task.status = RuntimeTaskStatus.RUNNING
        task.started_at = started_at
        task.updated_at = started_at

    def complete(self, task_id: str) -> None:
        task = self._tasks[task_id]
        ended_at = utc_now()
        task.status = RuntimeTaskStatus.COMPLETED
        task.ended_at = ended_at
        task.updated_at = ended_at

    def fail(self, task_id: str, error: str) -> None:
        task = self._tasks[task_id]
        ended_at = utc_now()
        task.status = RuntimeTaskStatus.FAILED
        task.error = error
        task.ended_at = ended_at
        task.updated_at = ended_at

    def interrupt(self, task_id: str, reason: str) -> None:
        task = self._tasks[task_id]
        ended_at = utc_now()
        task.status = RuntimeTaskStatus.INTERRUPTED
        task.error = reason
        task.ended_at = ended_at
        task.updated_at = ended_at

    def get(self, task_id: str) -> RuntimeTaskState | None:
        return self._tasks.get(task_id)

    def snapshot(self) -> dict[str, RuntimeTaskState]:
        return dict(self._tasks)

    def evict_terminal(self) -> None:
        for task_id, task in list(self._tasks.items()):
            if is_terminal_runtime_task_status(task.status):
                del self._tasks[task_id]


class AssignmentLifecycleController:
    """Coordinates runtime-task, agent, and todo lifecycle for one assignment."""

    def __init__(
        self,
        *,
        state: RunState,
        lifecycle: AgentLifecycle,
        registry: RuntimeTaskRegistry,
        todos: TodoQueue | None = None,
    ) -> None:
        self.state = state
        self.lifecycle = lifecycle
        self.registry = registry
        self.todos = todos or TodoQueue(state)

    def begin(
        self, *, cycle: int, todo: TodoItem, worker: WorkerAgent
    ) -> RuntimeTaskState:
        runtime_task = self.registry.register(
            RuntimeTaskState(
                task_id=self._task_id(cycle=cycle, todo=todo, worker=worker),
                type=RuntimeTaskType.WORKER_ASSIGNMENT,
                description=f"{todo.todo_id} -> {worker.name}",
                worker_name=worker.name,
                todo_id=todo.todo_id,
            )
        )
        self.registry.start(runtime_task.task_id)
        self.lifecycle.begin(worker.name, todo.todo_id)
        self.todos.start(todo, worker.name, touch=False)
        return runtime_task

    def complete(
        self,
        *,
        worker: WorkerAgent,
        runtime_task: RuntimeTaskState,
        result: WorkerResult,
    ) -> None:
        self.registry.complete(runtime_task.task_id)
        self.lifecycle.finish(worker.name, success=result.success, error=result.error)

    def transient_interrupt(
        self,
        *,
        todo: TodoItem,
        worker: WorkerAgent,
        runtime_task: RuntimeTaskState,
        reason: str,
    ) -> None:
        self.todos.release_transient(todo, reason, touch=False)
        self.registry.interrupt(runtime_task.task_id, reason)
        self.lifecycle.interrupt(worker.name, reason)

    def interrupt(
        self, *, worker: WorkerAgent, runtime_task: RuntimeTaskState, reason: str
    ) -> None:
        self.registry.interrupt(runtime_task.task_id, reason)
        self.lifecycle.interrupt(worker.name, reason)

    def fail(
        self, *, worker: WorkerAgent, runtime_task: RuntimeTaskState, error: str
    ) -> None:
        self.registry.fail(runtime_task.task_id, error)
        self.lifecycle.finish(worker.name, success=False, error=error)

    @staticmethod
    def _task_id(*, cycle: int, todo: TodoItem, worker: WorkerAgent) -> str:
        return f"worker:{cycle}:{todo.todo_id}:{worker.name}"
