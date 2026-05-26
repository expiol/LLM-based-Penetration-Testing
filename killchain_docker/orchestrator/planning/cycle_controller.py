"""Planner refresh control flow for one orchestration cycle."""

from __future__ import annotations

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.dispatch.types import (
    ExecutionEventsView,
    RunTerminationView,
)
from killchain_docker.orchestrator.planning.queue_refresh import (
    PlanningRefreshController,
)
from killchain_docker.orchestrator.planning.refresh_results import (
    DETERMINISTIC_BACKLOG_SUMMARY,
    PlanningCycleResult,
)
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState


class PlanningCycleController:
    """Owns planner refresh control flow for one orchestration cycle."""

    def __init__(
        self,
        *,
        state: RunState,
        todos: TodoQueue,
        refresh: PlanningRefreshController,
        events: ExecutionEventsView,
        termination: RunTerminationView,
    ) -> None:
        self.state = state
        self.todos = todos
        self.refresh = refresh
        self.events = events
        self.termination = termination
        self.outcome = RunOutcomeStore(state)
        self.metadata = RunMetadataStore(state)

    def plan(self, *, cycle: int) -> PlanningCycleResult:
        if self.todos.has_ready():
            self.events.emit(f"[cycle {cycle}] planner skipped - ready todo backlog")
            if self.metadata.consume_transient_skip() is not None:
                return PlanningCycleResult(summary=DETERMINISTIC_BACKLOG_SUMMARY)
            refresh = self.refresh.refresh_deterministic_seeds(cycle=cycle)
            return PlanningCycleResult(summary=refresh.summary)
        try:
            self.events.checkpoint_activity(f"[cycle {cycle}] planning next todos")
            refresh = self.refresh.refresh(cycle=cycle)
        except LLMClientError as exc:
            action = self.termination.handle_step_llm_error(
                cycle=cycle,
                source="planner",
                exc=exc,
                permanent_message=f"[cycle {cycle}] planner LLM error - aborting run",
            )
            return self._result_from_failure_action(action, exc=exc)
        self.termination.note_successful_step("planner")
        if refresh.stop_run and (self.outcome.is_solved or not self.todos.has_open()):
            self.events.emit(f"[cycle {cycle}] planner signalled stop - halting run")
            self.outcome.stopped("planner_stop", touch=False)
            self.events.checkpoint()
            return PlanningCycleResult(summary=refresh.summary, halt_run=True)
        return PlanningCycleResult(summary=refresh.summary)

    @staticmethod
    def _result_from_failure_action(
        action, *, exc: LLMClientError
    ) -> PlanningCycleResult:
        if action.retry_cycle:
            return PlanningCycleResult(
                summary=DETERMINISTIC_BACKLOG_SUMMARY,
                retry_cycle=True,
            )
        if action.halt_run:
            return PlanningCycleResult(summary="", halt_run=True)
        raise exc
