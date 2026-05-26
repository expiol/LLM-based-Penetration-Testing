"""Deterministic closure passes outside the routed loop."""

from __future__ import annotations

from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.assignment_execution import (
    AssignmentExecutionController,
)
from killchain_docker.orchestrator.closure_planner import closure_decision
from killchain_docker.orchestrator.closure_policy import DeterministicClosurePolicy
from killchain_docker.orchestrator.closure_queue import ClosureQueue
from killchain_docker.orchestrator.closure_rounds import ClosureRoundRecorder
from killchain_docker.orchestrator.closure_todo_execution import ClosureTodoExecutor
from killchain_docker.orchestrator.final_flag_validation import FinalFlagValidationPass
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.orchestrator.todo_queue_writer import TodoQueueWriter
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import WorkerAssignment, WorkerResult


class ClosureExecutionController:
    """Executes deterministic closure passes outside the main orchestration loop."""

    def __init__(
        self,
        *,
        state: RunState,
        todo_reader: TodoQueueReader,
        todo_writer: TodoQueueWriter,
        agent_directory: AgentDirectory,
        execution: AssignmentExecutionController,
        events: RuntimeEventController,
    ) -> None:
        self.state = state
        self.todo_reader = todo_reader
        self.todo_writer = todo_writer
        self.agent_directory = agent_directory
        self.execution = execution
        self.events = events
        self.outcome = RunOutcomeStore(state)
        journal = RunJournal(state)
        self.queue = ClosureQueue(writer=todo_writer, journal=journal)
        self.executor = ClosureTodoExecutor(
            state=state,
            reader=todo_reader,
            agent_directory=agent_directory,
            execution=execution,
            events=events,
        )
        self.rounds = ClosureRoundRecorder(state=state, journal=journal, events=events)
        self.final_validator = FinalFlagValidationPass(
            state=state,
            reader=todo_reader,
            writer=todo_writer,
            executor=self.executor,
            recorder=self.rounds,
            events=events,
        )

    def inline_deterministic_followup(
        self,
        *,
        cycle: int,
        remaining_budget: int,
        planner: object,
        max_assignments: int,
    ) -> tuple[list[WorkerResult], list[WorkerAssignment]]:
        if (
            self.outcome.is_solved
            or remaining_budget <= 0
            or self.todo_reader.has_ready()
            or (not DeterministicClosurePolicy.has_generated_artifact(self.state))
        ):
            return ([], [])
        budget = min(remaining_budget, max_assignments)
        decision = closure_decision(
            state=self.state,
            planner=planner,
            summary="Inline deterministic artifact follow-up.",
            note="Skipped LLM planning for inline deterministic artifact follow-up.",
            limit=budget,
        )
        if decision is None:
            return ([], [])
        proposed, created, created_ids = self.queue.enqueue_decision(decision)
        if not created_ids:
            return ([], [])
        self.events.emit(
            f"[cycle {cycle}] inline deterministic artifact follow-up: proposed={proposed} new={created}"
        )
        return self.executor.execute_created(
            cycle=cycle,
            created_ids=created_ids,
            budget=budget,
            assignment_rationale="inline deterministic artifact follow-up",
            event_label="inline deterministic",
        )

    def final_deterministic_evidence_pass(
        self, *, cycle: int, planner: object, max_passes: int, max_assignments: int
    ) -> bool:
        if self.outcome.is_solved or self.todo_reader.has_open():
            return False
        if not DeterministicClosurePolicy.has_generated_artifact(self.state):
            return False
        ran_any = False
        remaining_budget = max_assignments
        for pass_index in range(1, max_passes + 1):
            if (
                self.outcome.is_solved
                or self.todo_reader.has_open()
                or remaining_budget <= 0
            ):
                break
            decision = closure_decision(
                state=self.state,
                planner=planner,
                summary="Final deterministic evidence closure pass.",
                note="Skipped LLM planning for final deterministic evidence closure.",
                limit=remaining_budget,
            )
            if decision is None:
                break
            proposed, created, created_ids = self.queue.enqueue_decision(decision)
            if not created_ids:
                break
            self.events.emit(
                f"[cycle {cycle}] final deterministic evidence closure pass {pass_index}: proposed={proposed} new={created}"
            )
            results, assignments = self.executor.execute_created(
                cycle=cycle,
                created_ids=created_ids,
                budget=remaining_budget,
                assignment_rationale="final deterministic evidence closure",
                event_label="final closure",
            )
            remaining_budget -= len(results)
            if results:
                ran_any = True
                self.rounds.record(
                    cycle=cycle,
                    planner_summary="final deterministic evidence closure pass",
                    assignments=assignments,
                    results=results,
                )
            cycle += 1
        return ran_any

    def final_flag_validation_pass(self, *, cycle: int) -> bool:
        return self.final_validator.run(cycle=cycle)
