"""Typed dispatch contracts shared by queue, routing, and cycle controllers."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    RouterDecision,
    TodoItem,
    TodoPhase,
    todo_phase_rank,
)


class DependencyState(StrEnum):
    """Dependency state for queued todo readiness."""

    SATISFIED = "satisfied"
    WAITING = "waiting"
    UNSATISFIABLE = "unsatisfiable"


@dataclass(frozen=True)
class DependencyCheck:
    """Typed readiness result for one todo's dependencies."""

    state: DependencyState
    reason: str = ""

    @property
    def satisfied(self) -> bool:
        return self.state == DependencyState.SATISFIED

    @property
    def waiting(self) -> bool:
        return self.state == DependencyState.WAITING

    @property
    def unsatisfiable(self) -> bool:
        return self.state == DependencyState.UNSATISFIABLE


@dataclass(frozen=True)
class DependencyBlock:
    """A todo blocked because a dependency can never be satisfied."""

    todo: TodoItem
    reason: str


class EmptyDispatchAction(StrEnum):
    """What the orchestrator should do after an empty router decision."""

    CONTINUE = "continue"
    HALT = "halt"


@dataclass(frozen=True)
class EmptyDispatchResult:
    """Dispatch state transition after the router selected no work."""

    action: EmptyDispatchAction
    dependency_blocks: list[DependencyBlock] = field(default_factory=list)
    consecutive_empty_rounds: int = 0
    checkpoint: bool = False
    reason: str = ""

    @property
    def should_halt(self) -> bool:
        return self.action == EmptyDispatchAction.HALT

    @property
    def retry_cycle(self) -> bool:
        return not self.should_halt

    @property
    def halt_run(self) -> bool:
        return self.should_halt


@dataclass(frozen=True)
class DispatchCycleResult:
    """Control-flow result after routing and dispatching one cycle."""

    retry_cycle: bool = False
    halt_run: bool = False


@dataclass(frozen=True)
class QueuedTodoBatch:
    """Ready todos selected for one dispatch round."""

    todos: list[TodoItem]
    focus_phase: TodoPhase | None
    blocked_by_dependency: list[TodoItem] = field(default_factory=list)


def select_ready_batch(queue, *, max_assignments: int) -> QueuedTodoBatch:
    """Pick the next coherent batch of ready todos for a single dispatch round."""
    limit = max(1, max_assignments)
    ready = queue.ready(limit=None)
    if not ready:
        return QueuedTodoBatch(
            todos=[],
            focus_phase=None,
            blocked_by_dependency=queue.blocked_by_dependency(),
        )
    focus_phase = min((todo.phase for todo in ready), key=todo_phase_rank)
    todos = [todo for todo in ready if todo.phase == focus_phase][:limit]
    return QueuedTodoBatch(
        todos=todos,
        focus_phase=focus_phase,
        blocked_by_dependency=queue.blocked_by_dependency(),
    )


@dataclass(frozen=True)
class EnqueueReport:
    """Append-only queue result for a planner decision."""

    proposed: int
    created: int
    created_ids: list[str]

    @property
    def deduped(self) -> int:
        return self.proposed - self.created


class AgentDirectoryView(Protocol):
    @property
    def worker_names(self) -> set[str]: ...

    def workers_for_capability(self, capability: str) -> list[str]: ...

    def workers_for_profile(self, profile: str) -> list[str]: ...

    def select(
        self, worker_name: str, todo: TodoItem, state
    ) -> tuple[object | None, str]: ...


class ExecutionEventsView(Protocol):
    def emit(
        self, message: str, *, event_type: str | None = None, **context: object
    ) -> None: ...

    def checkpoint(self) -> None: ...

    def checkpoint_activity(self, message: str, **context: object) -> None: ...

    def todo_context(
        self, cycle: int, todo: TodoItem, *, worker: str | None = None
    ) -> dict[str, object]: ...


class RunTerminationView(Protocol):
    def handle_step_llm_error(
        self, *, cycle: int, source: str, exc: LLMClientError, permanent_message: str
    ): ...


class RouterView(Protocol):
    def route(
        self,
        state: RunState,
        *,
        agent_directory: AgentDirectoryView,
        max_assignments: int,
    ) -> RouterDecision: ...
