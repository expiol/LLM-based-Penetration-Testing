"""Worker agent runtime lifecycle state."""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from killchain_docker.state.common import utc_now


class AgentStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass
class AgentRuntimeState:
    """Current lifecycle view for one worker agent."""

    name: str
    status: AgentStatus = AgentStatus.IDLE
    current_todo_id: str | None = None
    last_error: str | None = None
    started_at: datetime | None = None
    updated_at: datetime = field(default_factory=utc_now)


class AgentLifecycle:
    """Lifecycle state machine for worker agents."""

    def __init__(self) -> None:
        self._states: dict[str, AgentRuntimeState] = {}

    def ensure(self, worker_name: str) -> AgentRuntimeState:
        if worker_name not in self._states:
            self._states[worker_name] = AgentRuntimeState(name=worker_name)
        return self._states[worker_name]

    def begin(self, worker_name: str, todo_id: str) -> None:
        state = self.ensure(worker_name)
        started_at = utc_now()
        state.status = AgentStatus.RUNNING
        state.current_todo_id = todo_id
        state.last_error = None
        state.started_at = started_at
        state.updated_at = started_at

    def finish(
        self, worker_name: str, *, success: bool, error: str | None = None
    ) -> None:
        state = self.ensure(worker_name)
        state.status = AgentStatus.COMPLETED if success else AgentStatus.FAILED
        state.current_todo_id = None
        state.last_error = error
        state.updated_at = utc_now()

    def interrupt(self, worker_name: str, reason: str) -> None:
        state = self.ensure(worker_name)
        state.status = AgentStatus.INTERRUPTED
        state.current_todo_id = None
        state.last_error = reason
        state.updated_at = utc_now()

    def snapshot(self) -> dict[str, AgentRuntimeState]:
        return dict(self._states)
