"""Final flag-validation closure pass."""

from __future__ import annotations

from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.closure_rounds import ClosureRoundRecorder
from killchain_docker.orchestrator.closure_todo_execution import ClosureTodoExecutor
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.orchestrator.todo_queue_writer import TodoQueueWriter
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase


class FinalFlagValidationPass:
    """Queue and execute final validation for ready candidates."""

    def __init__(
        self,
        *,
        state: RunState,
        reader: TodoQueueReader,
        writer: TodoQueueWriter,
        executor: ClosureTodoExecutor,
        recorder: ClosureRoundRecorder,
        events: RuntimeEventController,
    ) -> None:
        self.state = state
        self.reader = reader
        self.writer = writer
        self.executor = executor
        self.recorder = recorder
        self.events = events
        self.outcome = RunOutcomeStore(state)

    def run(self, *, cycle: int) -> bool:
        if self.outcome.is_solved or self.reader.has_open():
            return False
        queued = self._queue_candidates()
        if not queued:
            return False
        self.events.emit(
            f"[cycle {cycle}] final flag validation pass for {len(queued)} candidate(s)"
        )
        results, assignments = self.executor.execute_flag_validation(
            cycle=cycle, todos=queued
        )
        self.recorder.record(
            cycle=cycle,
            planner_summary="final flag validation pass",
            assignments=assignments,
            results=results,
        )
        return True

    def _queue_candidates(self) -> list[TodoItem]:
        queued: list[TodoItem] = []
        for candidate in CandidatePolicy.validation_ready_candidates(self.state):
            dedupe_key = f"final:flag-validation:{candidate.value}"
            if self.reader.has_dedupe_key(dedupe_key):
                continue
            queued.append(
                self.writer.enqueue(
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
