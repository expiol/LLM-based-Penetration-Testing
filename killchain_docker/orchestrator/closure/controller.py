"""Deterministic closure passes outside the routed loop."""

from __future__ import annotations

from collections.abc import Callable

from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.closure.policy import DeterministicClosurePolicy
from killchain_docker.orchestrator.execution import Execution
from killchain_docker.orchestrator.closure.final_flag_validation import FinalFlagValidationPass
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    RouterRound,
    RouterRoundSummary,
    TodoItem,
    WorkerAssignment,
    WorkerResult,
)


class ClosureExecutionController:
    """Executes deterministic closure passes outside the main orchestration loop."""

    def __init__(
        self,
        *,
        state: RunState,
        todos: TodoQueue,
        agent_directory: AgentDirectory,
        execution: Execution,
        events: RuntimeEventController,
        planner: object | None = None,
    ) -> None:
        self.state = state
        self.todos = todos
        self.agent_directory = agent_directory
        self.execution = execution
        self.events = events
        self.planner = planner
        self.journal = RunJournal(state)
        self.outcome = RunOutcomeStore(state)
        self.final_validator = FinalFlagValidationPass(
            state=state,
            todos=todos,
            agent_directory=agent_directory,
            execution=execution,
            recorder=self,
            events=events,
        )

    def inline_deterministic_followup(
        self,
        *,
        cycle: int,
        remaining_budget: int,
        planner: object | None = None,
        max_assignments: int,
    ) -> tuple[list[WorkerResult], list[WorkerAssignment]]:
        if (
            self.outcome.is_solved
            or remaining_budget <= 0
            or self.todos.has_ready()
            or (not DeterministicClosurePolicy.has_generated_artifact(self.state))
        ):
            return ([], [])
        budget = min(remaining_budget, max_assignments)
        decision = self._planner_decision(
            planner=planner or self.planner,
            summary="Inline deterministic artifact follow-up.",
            note="Skipped LLM planning for inline deterministic artifact follow-up.",
            limit=budget,
        )
        if decision is None:
            return ([], [])
        proposed, created, created_ids = self._enqueue_decision(decision)
        if not created_ids:
            return ([], [])
        self.events.emit(
            f"[cycle {cycle}] inline deterministic artifact follow-up: proposed={proposed} new={created}"
        )
        outcome = self._run_created_todos(
            cycle=cycle,
            created_ids=created_ids,
            budget=budget,
            assignment_rationale="inline deterministic artifact follow-up",
            event_label="inline deterministic",
        )
        return outcome.results, outcome.executed_assignments

    def final_deterministic_evidence_pass(
        self,
        *,
        cycle: int,
        planner: object | None = None,
        max_passes: int,
        max_assignments: int,
    ) -> bool:
        if self.outcome.is_solved or self.todos.has_open():
            return False
        if not DeterministicClosurePolicy.has_generated_artifact(self.state):
            return False
        ran_any = False
        remaining_budget = max_assignments
        for pass_index in range(1, max_passes + 1):
            if (
                self.outcome.is_solved
                or self.todos.has_open()
                or remaining_budget <= 0
            ):
                break
            decision = self._planner_decision(
                planner=planner or self.planner,
                summary="Final deterministic evidence closure pass.",
                note="Skipped LLM planning for final deterministic evidence closure.",
                limit=remaining_budget,
            )
            if decision is None:
                break
            proposed, created, created_ids = self._enqueue_decision(decision)
            if not created_ids:
                break
            self.events.emit(
                f"[cycle {cycle}] final deterministic evidence closure pass {pass_index}: proposed={proposed} new={created}"
            )
            outcome = self._run_created_todos(
                cycle=cycle,
                created_ids=created_ids,
                budget=remaining_budget,
                assignment_rationale="final deterministic evidence closure",
                event_label="final closure",
            )
            remaining_budget -= len(outcome.results)
            if outcome.results:
                ran_any = True
                self.record(
                    cycle=cycle,
                    planner_summary="final deterministic evidence closure pass",
                    assignments=outcome.executed_assignments,
                    results=outcome.results,
                )
            cycle += 1
        return ran_any

    def final_flag_validation_pass(self, *, cycle: int) -> bool:
        return self.final_validator.run(cycle=cycle)

    def record(
        self,
        *,
        cycle: int,
        planner_summary: str,
        assignments: list[WorkerAssignment],
        results: list[WorkerResult],
    ) -> None:
        """Write a synthetic router round for closure-only execution."""
        self.journal.round(
            RouterRound(
                cycle=cycle,
                planner_summary=planner_summary,
                assignments=assignments,
                results=results,
                summary=RouterRoundSummary(
                    summary="; ".join((result.summary for result in results)),
                    direct_results=[result.summary for result in results],
                ),
            )
        )
        RunStateMaintenance(self.state).touch()
        self.events.checkpoint()

    def _planner_decision(
        self,
        *,
        planner: object | None,
        summary: str,
        note: str,
        limit: int,
    ) -> PlannerDecision | None:
        merge = _planner_merge(planner)
        if merge is None:
            return None
        decision = merge(
            self.state,
            llm_decision=PlannerDecision(summary=summary, todos=[], notes=[note]),
        )
        filtered = [
            todo
            for todo in decision.todos
            if DeterministicClosurePolicy.is_final_closure_todo(todo)
        ][:limit]
        if not filtered:
            return None
        return PlannerDecision(summary=summary, todos=filtered, notes=decision.notes)

    def _enqueue_decision(
        self, decision: PlannerDecision
    ) -> tuple[int, int, list[str]]:
        report = self.todos.enqueue_planned(decision.todos)
        if decision.notes:
            self.journal.orchestration_notes(decision.notes)
        return (report.proposed, report.created, report.created_ids)

    def _run_created_todos(
        self,
        *,
        cycle: int,
        created_ids: list[str],
        budget: int,
        assignment_rationale: str,
        event_label: str,
    ):
        todos: list[TodoItem] = []
        for todo_id in created_ids:
            todo = self.todos.get(todo_id)
            if todo is not None:
                todos.append(todo)

        def select_worker(todo: TodoItem):
            worker, worker_name, reason = DeterministicClosurePolicy.select_worker(
                todo=todo, state=self.state, agent_directory=self.agent_directory
            )
            return worker, worker_name or "deterministic-worker", reason

        return self.execution.run_assignments(
            cycle=cycle,
            todos=todos,
            select_worker=select_worker,
            rationale=assignment_rationale,
            event_label=event_label,
            budget=budget,
        )


def _planner_merge(planner: object | None) -> Callable[..., PlannerDecision] | None:
    if planner is None:
        return None
    pipeline = getattr(planner, "pipeline", None)
    merge = getattr(pipeline, "merge", None)
    return merge if callable(merge) else None
