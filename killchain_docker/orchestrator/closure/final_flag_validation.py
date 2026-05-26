"""Final flag-validation closure pass."""

from __future__ import annotations

from typing import Protocol

from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.execution import Execution
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    TodoItem,
    TodoPhase,
    WorkerAssignment,
    WorkerResult,
)


class _RoundRecorder(Protocol):
    def record(
        self,
        *,
        cycle: int,
        planner_summary: str,
        assignments: list[WorkerAssignment],
        results: list[WorkerResult],
    ) -> None: ...


class FinalFlagValidationPass:
    """Queue and execute final validation for ready candidates."""

    def __init__(
        self,
        *,
        state: RunState,
        todos: TodoQueue,
        agent_directory: AgentDirectory,
        execution: Execution,
        recorder: _RoundRecorder,
        events: RuntimeEventController,
    ) -> None:
        self.state = state
        self.todos = todos
        self.agent_directory = agent_directory
        self.execution = execution
        self.recorder = recorder
        self.events = events
        self.outcome = RunOutcomeStore(state)

    def run(self, *, cycle: int) -> bool:
        if self.outcome.is_solved or self.todos.has_open():
            return False
        queued = self._queue_candidates()
        if not queued:
            return False
        self.events.emit(
            f"[cycle {cycle}] final flag validation pass for {len(queued)} candidate(s)"
        )

        def select_worker(todo: TodoItem):
            worker, reason = self.agent_directory.select(
                "flag-worker", todo, self.state
            )
            return worker, "flag-worker", reason

        outcome = self.execution.run_assignments(
            cycle=cycle,
            todos=queued,
            select_worker=select_worker,
            rationale="final validation pass",
            event_label="final validation",
        )
        self.recorder.record(
            cycle=cycle,
            planner_summary="final flag validation pass",
            assignments=outcome.executed_assignments,
            results=outcome.results,
        )
        return True

    def _queue_candidates(self) -> list[TodoItem]:
        queued: list[TodoItem] = []
        for candidate in CandidatePolicy.validation_ready_candidates(self.state):
            dedupe_key = f"final:flag-validation:{candidate.value}"
            if self.todos.has_dedupe_key(dedupe_key):
                continue
            queued.append(
                self.todos.enqueue(
                    TodoItem(
                        goal="Validate recovered flag candidate.",
                        phase=TodoPhase.FLAG_VALIDATION,
                        priority=100,
                        context={
                            "candidate_flag": candidate.value,
                            "flag_candidate_id": candidate.candidate_id,
                            "family": "flag-validation",
                        },
                        success_criteria=[
                            "Confirm whether the candidate is the challenge flag."
                        ],
                        constraints=[
                            "Validate only grounded candidates already present in state."
                        ],
                        dedupe_key=dedupe_key,
                    )
                )
            )
        return queued
