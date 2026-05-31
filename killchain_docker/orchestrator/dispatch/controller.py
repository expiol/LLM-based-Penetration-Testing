"""Routing, execution, and round completion for one orchestration cycle."""

from __future__ import annotations

from collections.abc import Callable

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.dispatch.batches import (
    assignment_execution_batches,
)
from killchain_docker.orchestrator.closure.controller import ClosureExecutionController
from killchain_docker.orchestrator.dispatch.types import (
    AgentDirectoryView,
    DependencyBlock,
    DispatchCycleResult,
    EmptyDispatchAction,
    EmptyDispatchResult,
    ExecutionEventsView,
    RouterView,
    RunTerminationView,
)
from killchain_docker.orchestrator.execution import (
    BatchExecutionOutcome,
    Execution,
    TransientLLMHandling,
)
from killchain_docker.orchestrator.progress.run_progress import RunProgressController
from killchain_docker.orchestrator.run_termination import (
    LLMFailureAction,
    RunTerminationController,
)
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    RouterRound,
    WorkerAssignment,
    WorkerResult,
)


class DispatchCycleController:
    """Owns routing, empty-dispatch recovery, execution, and round completion."""

    DEFAULT_INLINE_DETERMINISTIC_FOLLOWUP_ASSIGNMENTS = 4

    def __init__(
        self,
        *,
        state: RunState,
        router: RouterView,
        agent_directory: AgentDirectoryView,
        events: ExecutionEventsView,
        termination: RunTerminationController | RunTerminationView,
        execution: Execution,
        transient_llm: TransientLLMHandling,
        closure: ClosureExecutionController,
        progress: RunProgressController,
        planner: object,
        assignment_budget: Callable[[], int],
        max_consecutive_empty_rounds: int,
        journal: RunJournal,
        inline_followup_assignments: int = DEFAULT_INLINE_DETERMINISTIC_FOLLOWUP_ASSIGNMENTS,
    ) -> None:
        self.state = state
        self.router = router
        self.agent_directory = agent_directory
        self.events = events
        self.termination = termination
        self.execution = execution
        self.transient_llm = transient_llm
        self.closure = closure
        self.progress = progress
        self.planner = planner
        self.assignment_budget = assignment_budget
        self.max_consecutive_empty_rounds = max(1, max_consecutive_empty_rounds)
        self.consecutive_empty_rounds = 0
        self.inline_followup_assignments = max(0, inline_followup_assignments)
        self.journal = journal
        self.todos = TodoQueue(state)
        self.outcome = RunOutcomeStore(state)

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
            return self._cycle_result_from_failure_action(action, exc=exc)
        self.termination.note_successful_step("router")
        if not decision.assignments:
            empty = self._handle_no_assignments(cycle=cycle)
            return DispatchCycleResult(
                retry_cycle=not empty.halt_run,
                halt_run=empty.halt_run,
            )
        self.consecutive_empty_rounds = 0
        round_execution = self._execute_routed_batches(
            cycle=cycle, assignments=decision.assignments
        )
        return self._complete_round(
            cycle=cycle,
            planner_summary=planner_summary,
            round_execution=round_execution,
        )

    def _handle_no_assignments(self, *, cycle: int) -> EmptyDispatchResult:
        result = self._handle_empty_decision()
        for block in result.dependency_blocks:
            self.events.emit(
                f"[cycle {cycle}] dependency blocked {block.todo.todo_id}: {block.reason}",
                event_type="todo_dependency_blocked",
                **self.events.todo_context(cycle, block.todo),
            )
        if result.dependency_blocks:
            self.events.checkpoint()
            return result
        self.events.emit(f"[cycle {cycle}] router selected no assignments")
        self.events.checkpoint()
        if result.reason == "router_no_assignments":
            self.outcome.failed("router_no_assignments", touch=False)
            self.todos.block_open("router_no_assignments")
        return result

    def _handle_empty_decision(self) -> EmptyDispatchResult:
        dependency_blocks = self.todos.block_unsatisfiable_dependencies()
        if dependency_blocks:
            self.consecutive_empty_rounds = 0
            action = (
                EmptyDispatchAction.CONTINUE
                if self.todos.has_open()
                else EmptyDispatchAction.HALT
            )
            return EmptyDispatchResult(
                action=action,
                dependency_blocks=dependency_blocks,
                consecutive_empty_rounds=self.consecutive_empty_rounds,
                checkpoint=True,
                reason="dependency_blocked",
            )
        self.consecutive_empty_rounds += 1
        if self.consecutive_empty_rounds >= self.max_consecutive_empty_rounds:
            return EmptyDispatchResult(
                action=EmptyDispatchAction.HALT,
                consecutive_empty_rounds=self.consecutive_empty_rounds,
                checkpoint=True,
                reason="router_no_assignments",
            )
        return EmptyDispatchResult(
            action=EmptyDispatchAction.CONTINUE,
            consecutive_empty_rounds=self.consecutive_empty_rounds,
            checkpoint=True,
            reason="router_empty",
        )

    def _execute_routed_batches(
        self, *, cycle: int, assignments: list[WorkerAssignment]
    ) -> BatchExecutionOutcome:
        all_results: list[WorkerResult] = []
        all_executed: list[WorkerAssignment] = []
        todos_by_id = {}
        rationale_by_id = {}
        worker_name_by_id = {}
        for assignment in assignments:
            todo = self.todos.get(assignment.todo_id)
            if todo is None:
                self.journal.orchestration_note(
                    f"cycle {cycle}: assignment referenced unknown todo {assignment.todo_id}"
                )
                continue
            todos_by_id[assignment.todo_id] = todo
            rationale_by_id[assignment.todo_id] = assignment.rationale
            worker_name_by_id[assignment.todo_id] = assignment.worker_name

        def select_worker(todo):
            worker_name = worker_name_by_id[todo.todo_id]
            worker, reason = self.agent_directory.select(
                worker_name, todo, self.state
            )
            return worker, worker_name, reason

        def rationale_for(todo):
            return rationale_by_id[todo.todo_id]

        for batch in assignment_execution_batches(assignments, todos_by_id):
            batch_todos = [
                todos_by_id[assignment.todo_id]
                for assignment in batch.assignments
                if assignment.todo_id in todos_by_id
            ]
            if not batch_todos:
                continue
            outcome = self.execution.run_assignments(
                cycle=cycle,
                todos=batch_todos,
                select_worker=select_worker,
                rationale=rationale_for,
                event_label="concurrent" if batch.concurrent else None,
                transient_llm=self.transient_llm,
                concurrent=batch.concurrent,
            )
            all_results.extend(outcome.results)
            all_executed.extend(outcome.executed_assignments)
            if outcome.stop_round:
                return BatchExecutionOutcome(
                    results=all_results,
                    executed_assignments=all_executed,
                    solved=outcome.solved,
                    transient_skip=outcome.transient_skip,
                    terminal_error=outcome.terminal_error,
                )
        return BatchExecutionOutcome(
            results=all_results,
            executed_assignments=all_executed,
            solved=self.execution.outcome.is_solved,
        )

    def _complete_round(
        self,
        *,
        cycle: int,
        planner_summary: str,
        round_execution: BatchExecutionOutcome,
    ) -> DispatchCycleResult:
        if round_execution.terminal_error or self.outcome.has_stop_reason(
            "llm_transient_error"
        ):
            return DispatchCycleResult(halt_run=True)
        if round_execution.transient_skip:
            self.events.checkpoint()
            return DispatchCycleResult(
                retry_cycle=True,
                transient_skip=True,
                consume_budget=bool(round_execution.results),
            )
        if round_execution.solved or self.outcome.is_solved:
            return DispatchCycleResult(halt_run=True)
        results = list(round_execution.results)
        executed_assignments = list(round_execution.executed_assignments)
        followup = self._run_inline_followup(
            cycle=cycle,
            results=results,
            executed_assignments=executed_assignments,
        )
        if followup.retry_cycle or followup.halt_run:
            return followup
        if self.outcome.is_solved:
            return DispatchCycleResult(halt_run=True)
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
            return self._cycle_result_from_failure_action(action, exc=exc)
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
            return DispatchCycleResult(halt_run=True)
        return DispatchCycleResult()

    def _run_inline_followup(
        self,
        *,
        cycle: int,
        results: list[WorkerResult],
        executed_assignments: list[WorkerAssignment],
    ) -> DispatchCycleResult:
        route_budget = max(1, int(self.assignment_budget()))
        followup_budget = max(0, route_budget - len(results))
        if not followup_budget:
            return DispatchCycleResult()
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
            return self._cycle_result_from_failure_action(action, exc=exc)
        if followup_results:
            results.extend(followup_results)
            executed_assignments.extend(followup_assignments)
        return DispatchCycleResult()

    @staticmethod
    def _cycle_result_from_failure_action(
        action: LLMFailureAction, *, exc: LLMClientError
    ) -> DispatchCycleResult:
        if action.retry_cycle:
            return DispatchCycleResult(retry_cycle=True, transient_skip=True)
        if action.halt_run:
            return DispatchCycleResult(halt_run=True)
        raise exc
