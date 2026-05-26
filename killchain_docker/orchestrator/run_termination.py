"""Run termination state transitions and LLM failure policy."""

from __future__ import annotations

from enum import StrEnum

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult


class LLMFailureAction(StrEnum):
    """Control-flow decision after an orchestration-step LLM failure."""

    RETRY_CYCLE = "retry_cycle"
    HALT_RUN = "halt_run"
    RAISE = "raise"

    @property
    def retry_cycle(self) -> bool:
        return self == LLMFailureAction.RETRY_CYCLE

    @property
    def halt_run(self) -> bool:
        return self == LLMFailureAction.HALT_RUN


class RunTerminationController:
    """Owns terminal run-state transitions and LLM failure records."""

    DEFAULT_LLM_ERROR_MESSAGE_LIMIT = 1200
    DEFAULT_MAX_TRANSIENT_SKIPS = 3

    def __init__(
        self,
        state: RunState,
        *,
        events: RuntimeEventController | None = None,
        llm_error_message_limit: int = DEFAULT_LLM_ERROR_MESSAGE_LIMIT,
        max_transient_skips: int = DEFAULT_MAX_TRANSIENT_SKIPS,
    ) -> None:
        self.state = state
        self.events = events
        self.outcome = RunOutcomeStore(state)
        self.metadata = RunMetadataStore(state)
        self.llm_error_message_limit = max(1, llm_error_message_limit)
        self.max_transient_skips = max(0, max_transient_skips)
        self.transient_skip_count = 0

    def skip_transient_llm_error(
        self, cycle: int, source: str, exc: LLMClientError
    ) -> bool:
        if not exc.transient or self.transient_skip_count >= self.max_transient_skips:
            return False
        self.transient_skip_count += 1
        self.metadata.remember_transient_skip(cycle=cycle, source=source, exc=exc)
        if self.events is not None:
            self.events.emit(
                f"[cycle {cycle}] transient LLM error in {source} "
                f"(skip {self.transient_skip_count}/{self.max_transient_skips}), "
                f"continuing next cycle: {exc}"
            )
        RunJournal(self.state).orchestration_note(
            f"cycle {cycle}: transient LLM error skipped in {source} "
            f"({self.transient_skip_count}/{self.max_transient_skips})"
        )
        return True

    def handle_step_llm_error(
        self,
        *,
        cycle: int,
        source: str,
        exc: LLMClientError,
        permanent_message: str,
        todo: TodoItem | None = None,
    ) -> LLMFailureAction:
        """Apply the standard planner/router/summarizer LLM failure policy."""
        if self.skip_transient_llm_error(cycle, source, exc):
            self._checkpoint()
            return LLMFailureAction.RETRY_CYCLE
        if exc.transient:
            self.halt_after_transient_llm_error(cycle, source, exc, todo=todo)
            self._checkpoint()
            return LLMFailureAction.HALT_RUN
        if self.events is not None:
            self.events.emit(permanent_message)
        self.mark_llm_error(cycle, source, exc)
        self._checkpoint()
        return LLMFailureAction.RAISE

    def remember_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> str:
        kind = str(getattr(exc, "kind", "unknown"))
        message = self._compact_llm_error(exc)
        reason = f"llm_error:{source}:{kind}:{type(exc).__name__}: {message}"
        self.metadata.remember_llm_error(
            cycle=cycle, source=source, exc=exc, message=message
        )
        RunJournal(self.state).orchestration_note(f"cycle {cycle}: {reason}")
        return reason

    def mark_llm_error(self, cycle: int, source: str, exc: LLMClientError) -> str:
        reason = self.remember_llm_error(cycle, source, exc)
        self.outcome.failed("llm_error", touch=False)
        todos = TodoQueue(self.state)
        todos.fail_running(reason, retryable=False)
        todos.block_open("llm_error")
        RunStateMaintenance(self.state).touch()
        return reason

    def halt_after_transient_llm_error(
        self,
        cycle: int,
        source: str,
        exc: LLMClientError,
        *,
        todo: TodoItem | None = None,
    ) -> str:
        reason = self.remember_llm_error(cycle, source, exc)
        self.outcome.failed("llm_transient_error", touch=False)
        TodoQueue(self.state).halt_for_transient_error(reason, todo=todo)
        if self.events is not None:
            self.events.emit(
                f"[cycle {cycle}] transient LLM error budget exhausted in {source}; "
                "ending run as llm_transient_error without marking task logic failed",
                event_type="llm_transient_error",
            )
        RunStateMaintenance(self.state).touch()
        return reason

    def worker_llm_error_result(
        self, *, cycle: int, todo: TodoItem, worker_name: str, exc: LLMClientError
    ) -> WorkerResult:
        reason = self.remember_llm_error(cycle, worker_name, exc)
        return WorkerResult(
            todo_id=todo.todo_id,
            worker_name=worker_name,
            success=False,
            summary=f"{worker_name} LLM error while selecting or running a tool",
            error=reason,
            retryable=False,
            result_quality="llm_error",
        )

    def finalize(self, *, max_cycles_exhausted: bool) -> None:
        todos = TodoQueue(self.state)
        open_todos = todos.has_open()
        terminal_unsolved_todos = todos.has_terminal_unsolved()
        terminal_unsolved_reason = todos.terminal_unsolved_reason()
        self.outcome.finalize_terminal(
            max_cycles_exhausted=max_cycles_exhausted,
            has_open_todos=open_todos,
            has_terminal_unsolved_todos=terminal_unsolved_todos,
            terminal_unsolved_reason=terminal_unsolved_reason,
        )
        if max_cycles_exhausted and open_todos:
            todos.block_open("max_cycles_exhausted")
            RunJournal(self.state).orchestration_note("max_cycles_exhausted")
        RunStateMaintenance(self.state).touch()

    def _checkpoint(self) -> None:
        if self.events is not None:
            self.events.checkpoint()

    def _compact_llm_error(self, exc: LLMClientError) -> str:
        message = str(exc).strip() or type(exc).__name__
        if len(message) <= self.llm_error_message_limit:
            return message
        return f"{message[: self.llm_error_message_limit].rstrip()}... [truncated]"
