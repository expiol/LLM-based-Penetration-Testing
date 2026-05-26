"""Post-processing for one routed assignment batch."""

from __future__ import annotations
from collections.abc import Callable
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.closure_controller import ClosureExecutionController
from killchain_docker.orchestrator.runtime_results import (
    RoutedAssignmentBatchResult,
    RoutedRoundCompletionResult,
)
from killchain_docker.orchestrator.run_progress import RunProgressController
from killchain_docker.orchestrator.run_termination import (
    LLMFailureAction,
    RunTerminationController,
)
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import RouterRound, WorkerAssignment, WorkerResult
from killchain_docker.state.outcome import RunOutcomeStore


class RoutedRoundCompletionController:
    """Owns post-processing after one routed assignment batch executes."""

    DEFAULT_INLINE_DETERMINISTIC_FOLLOWUP_ASSIGNMENTS = 4

    def __init__(
        self,
        *,
        state: RunState,
        closure: ClosureExecutionController,
        termination: RunTerminationController,
        progress: RunProgressController,
        journal: RunJournal,
        router: object,
        planner: object,
        route_assignment_budget: Callable[[], int],
        inline_followup_assignments: int = DEFAULT_INLINE_DETERMINISTIC_FOLLOWUP_ASSIGNMENTS,
    ) -> None:
        self.state = state
        self.closure = closure
        self.events = closure.events
        self.termination = termination
        self.progress = progress
        self.journal = journal
        self.router = router
        self.planner = planner
        self.route_assignment_budget = route_assignment_budget
        self.inline_followup_assignments = max(0, inline_followup_assignments)
        self.outcome = RunOutcomeStore(state)

    def complete(
        self,
        *,
        cycle: int,
        planner_summary: str,
        round_execution: RoutedAssignmentBatchResult,
    ) -> RoutedRoundCompletionResult:
        if round_execution.terminal_error or self.outcome.has_stop_reason(
            "llm_transient_error"
        ):
            return RoutedRoundCompletionResult(halt_run=True)
        if round_execution.transient_skip:
            self.events.checkpoint()
            return RoutedRoundCompletionResult(retry_cycle=True)
        if round_execution.solved or self.outcome.is_solved:
            return RoutedRoundCompletionResult(halt_run=True)
        results = list(round_execution.results)
        executed_assignments = list(round_execution.executed_assignments)
        followup_result = self._run_inline_followup(
            cycle=cycle, results=results, executed_assignments=executed_assignments
        )
        if followup_result.retry_cycle or followup_result.halt_run:
            return followup_result
        if self.outcome.is_solved:
            return RoutedRoundCompletionResult(halt_run=True)
        try:
            self.events.checkpoint_activity(
                f"[cycle {cycle}] summarizing worker results"
            )
            round_summary = self.router.summarize_round(self.state, results=results)
        except LLMClientError as exc:
            action = self.termination.handle_step_llm_error(
                cycle=cycle,
                source="round_summarizer",
                exc=exc,
                permanent_message=f"[cycle {cycle}] round summarizer LLM error - aborting run",
            )
            return self._completion_from_failure_action(action, exc=exc)
        self.journal.round(
            RouterRound(
                cycle=cycle,
                planner_summary=planner_summary,
                assignments=executed_assignments,
                results=results,
                summary=round_summary,
            )
        )
        self.events.emit(
            f"[cycle {cycle}] router summary: {round_summary.summary[:240]}"
        )
        self.progress.observe_round(cycle=cycle, results=results)
        self.events.checkpoint()
        if self.outcome.is_solved:
            return RoutedRoundCompletionResult(halt_run=True)
        return RoutedRoundCompletionResult()

    def _run_inline_followup(
        self,
        *,
        cycle: int,
        results: list[WorkerResult],
        executed_assignments: list[WorkerAssignment],
    ) -> RoutedRoundCompletionResult:
        route_budget = max(1, int(self.route_assignment_budget()))
        followup_budget = max(0, route_budget - len(results))
        if not followup_budget:
            return RoutedRoundCompletionResult()
        try:
            followup_results, followup_assignments = (
                self.closure.inline_deterministic_followup(
                    cycle=cycle,
                    remaining_budget=followup_budget,
                    planner=self.planner,
                    max_assignments=self.inline_followup_assignments,
                )
            )
        except LLMClientError as exc:
            action = self.termination.handle_step_llm_error(
                cycle=cycle,
                source="inline_deterministic_followup",
                exc=exc,
                permanent_message=f"[cycle {cycle}] inline deterministic follow-up LLM error - aborting run",
            )
            return self._completion_from_failure_action(action, exc=exc)
        if followup_results:
            results.extend(followup_results)
            executed_assignments.extend(followup_assignments)
        return RoutedRoundCompletionResult()

    @staticmethod
    def _completion_from_failure_action(
        action: LLMFailureAction, *, exc: LLMClientError
    ) -> RoutedRoundCompletionResult:
        if action.retry_cycle:
            return RoutedRoundCompletionResult(retry_cycle=True)
        if action.halt_run:
            return RoutedRoundCompletionResult(halt_run=True)
        raise exc
