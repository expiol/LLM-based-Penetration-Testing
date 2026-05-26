"""Routing, routed execution, and round completion for one cycle."""

from __future__ import annotations

from typing import Callable

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.dispatch_types import (
    AgentDirectoryView,
    DispatchCycleResult,
    ExecutionEventsView,
    RoutedExecutionView,
    RoundCompletionView,
    RouterView,
    RunTerminationView,
)
from killchain_docker.orchestrator.empty_dispatch import EmptyDispatchController
from killchain_docker.state.run_state import RunState


class DispatchCycleController:
    """Owns routing, empty-dispatch recovery, execution, and round completion."""

    def __init__(
        self,
        *,
        state: RunState,
        router: RouterView,
        agent_directory: AgentDirectoryView,
        events: ExecutionEventsView,
        termination: RunTerminationView,
        empty_dispatch: EmptyDispatchController,
        routed_execution: RoutedExecutionView,
        round_completion: RoundCompletionView,
        assignment_budget: Callable[[], int],
    ) -> None:
        self.state = state
        self.router = router
        self.agent_directory = agent_directory
        self.events = events
        self.termination = termination
        self.empty_dispatch = empty_dispatch
        self.routed_execution = routed_execution
        self.round_completion = round_completion
        self.assignment_budget = assignment_budget

    def dispatch(self, *, cycle: int, planner_summary: str) -> DispatchCycleResult:
        try:
            self.events.checkpoint_activity(f"[cycle {cycle}] routing ready todos")
            decision = self.router.route(
                self.state,
                agent_directory=self.agent_directory,
                max_assignments=max(1, int(self.assignment_budget())),
            )
        except LLMClientError as exc:
            action = self.termination.handle_step_llm_error(
                cycle=cycle,
                source="router",
                exc=exc,
                permanent_message=f"[cycle {cycle}] router LLM error - aborting run",
            )
            return self._result_from_failure_action(action, exc=exc)
        if not decision.assignments:
            empty_dispatch = self.empty_dispatch.handle_no_assignments(cycle=cycle)
            return DispatchCycleResult(
                retry_cycle=not empty_dispatch.halt_run,
                halt_run=empty_dispatch.halt_run,
            )
        self.empty_dispatch.rounds.reset_empty_rounds()
        round_execution = self.routed_execution.execute(
            cycle=cycle, assignments=decision.assignments
        )
        completion = self.round_completion.complete(
            cycle=cycle,
            planner_summary=planner_summary,
            round_execution=round_execution,
        )
        return DispatchCycleResult(
            retry_cycle=completion.retry_cycle, halt_run=completion.halt_run
        )

    @staticmethod
    def _result_from_failure_action(
        action, *, exc: LLMClientError
    ) -> DispatchCycleResult:
        if action.retry_cycle:
            return DispatchCycleResult(retry_cycle=True)
        if action.halt_run:
            return DispatchCycleResult(halt_run=True)
        raise exc
