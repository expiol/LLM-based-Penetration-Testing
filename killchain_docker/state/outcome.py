"""Run outcome store.

RunState stores durable lifecycle fields. RunOutcomeStore owns the write
policy for status, stop reason, solved flag, validation result, and runtime
error metadata so orchestrator modules do not duplicate terminal-state rules.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.run_state import RunStatus

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState
TERMINAL_RUN_STATUSES = frozenset(
    {
        RunStatus.COMPLETED,
        RunStatus.SOLVED,
        RunStatus.FAILED,
        RunStatus.STOPPED,
        RunStatus.INTERRUPTED,
    }
)


class RunOutcomeStore:
    """Mutable store for run lifecycle outcome fields."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)
        self.metadata = RunMetadataStore(state)

    def start(self, *, touch: bool = True) -> None:
        self.state.status = RunStatus.RUNNING
        if touch:
            self.maintenance.touch()

    def cycle_started(self, *, at, touch: bool = True) -> None:
        self.state.last_cycle_at = at
        if touch:
            self.maintenance.touch()

    @property
    def is_solved(self) -> bool:
        return self.state.solved

    @property
    def status_value(self) -> RunStatus:
        return self.state.status

    def has_stop_reason(self, reason: str) -> bool:
        return self.state.stop_reason == reason

    def solved_message(self, *, cycle: int) -> str:
        return f"[cycle {cycle}] solved: {self.state.validated_flag}"

    def summary_payload(self) -> dict[str, object]:
        return {
            "status": str(self.state.status),
            "stop_reason": self.state.stop_reason,
            "solved": self.state.solved,
            "validated_flag": self.state.validated_flag,
        }

    def solved(
        self, *, validated_flag: str | None, reason: str, touch: bool = True
    ) -> None:
        self.state.solved = True
        self.state.status = RunStatus.SOLVED
        if validated_flag:
            self.state.validated_flag = validated_flag
        self.state.stop_reason = reason
        if touch:
            self.maintenance.touch()

    def validated_flag(self, value: str, *, touch: bool = True) -> None:
        self.state.validated_flag = value
        if touch:
            self.maintenance.touch()

    def failed(self, reason: str, *, touch: bool = True) -> None:
        self.state.status = RunStatus.FAILED
        self.state.stop_reason = reason
        if touch:
            self.maintenance.touch()

    def stopped(self, reason: str, *, touch: bool = True) -> None:
        self.state.status = RunStatus.STOPPED
        self.state.stop_reason = reason
        if touch:
            self.maintenance.touch()

    def interrupted(self, reason: str = "interrupted", *, touch: bool = True) -> None:
        self.state.status = RunStatus.INTERRUPTED
        self.state.stop_reason = reason
        if touch:
            self.maintenance.touch()

    def runtime_exception(self, exc: BaseException, *, touch: bool = True) -> str:
        error = self.metadata.remember_runtime_error(exc)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            if self.state.status not in TERMINAL_RUN_STATUSES:
                self.state.status = RunStatus.INTERRUPTED
            self.state.stop_reason = self.state.stop_reason or "interrupted"
            note = f"run interrupted by {error['type']}"
        else:
            if self.state.status not in TERMINAL_RUN_STATUSES:
                self.state.status = RunStatus.FAILED
            self.state.stop_reason = self.state.stop_reason or (
                "llm_error"
                if exc.__class__.__name__ == "LLMClientError"
                else "runtime_error"
            )
            note = f"run failed with {error['type']}: {error['message']}"
        if touch:
            self.maintenance.touch()
        return note

    def ensure_terminal_reason(
        self, default_reason: str, *, touch: bool = True
    ) -> None:
        self.state.stop_reason = self.state.stop_reason or default_reason
        if touch:
            self.maintenance.touch()

    def finish_from_existing_reason(self, reason: str, *, touch: bool = True) -> None:
        self.state.stop_reason = reason
        self.state.status = (
            RunStatus.COMPLETED
            if reason == "unsolved_no_work_remaining"
            else RunStatus.FAILED
        )
        if touch:
            self.maintenance.touch()

    def finalize_terminal(
        self,
        *,
        max_cycles_exhausted: bool,
        has_open_todos: bool,
        has_terminal_unsolved_todos: bool,
        terminal_unsolved_reason: str,
    ) -> None:
        if max_cycles_exhausted and has_open_todos:
            self.failed("max_cycles_exhausted", touch=False)
        if self.state.solved:
            self.solved(
                validated_flag=self.state.validated_flag,
                reason=self.state.stop_reason or "solved",
                touch=False,
            )
        elif self.state.status == RunStatus.INTERRUPTED:
            self.ensure_terminal_reason("interrupted", touch=False)
        elif self.state.status == RunStatus.STOPPED:
            self.ensure_terminal_reason("planner_stop", touch=False)
        elif self.state.stop_reason == "llm_error":
            self.failed("llm_error", touch=False)
        elif self.state.stop_reason == "max_cycles_exhausted":
            self.failed("max_cycles_exhausted", touch=False)
        elif self.state.stop_reason == "router_no_assignments":
            self.failed("router_no_assignments", touch=False)
        elif has_open_todos:
            self.failed(self.state.stop_reason or "open_todos_remaining", touch=False)
        elif has_terminal_unsolved_todos:
            self.failed(self.state.stop_reason or terminal_unsolved_reason, touch=False)
        else:
            reason = self.state.stop_reason or terminal_unsolved_reason
            self.finish_from_existing_reason(reason, touch=False)


__all__ = ["RunOutcomeStore", "TERMINAL_RUN_STATUSES"]
