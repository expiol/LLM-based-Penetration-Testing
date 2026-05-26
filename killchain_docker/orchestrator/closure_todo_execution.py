"""Execute closure todos with deterministic worker selection."""

from __future__ import annotations

from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.assignment_execution import (
    AssignmentExecutionController,
)
from killchain_docker.orchestrator.closure_policy import DeterministicClosurePolicy
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    TodoItem,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
)


class ClosureTodoExecutor:
    """Run closure todos and apply their worker results."""

    def __init__(
        self,
        *,
        state: RunState,
        reader: TodoQueueReader,
        agent_directory: AgentDirectory,
        execution: AssignmentExecutionController,
        events: RuntimeEventController,
    ) -> None:
        self.state = state
        self.reader = reader
        self.agent_directory = agent_directory
        self.execution = execution
        self.events = events
        self.outcome = RunOutcomeStore(state)

    def execute_created(
        self,
        *,
        cycle: int,
        created_ids: list[str],
        budget: int,
        assignment_rationale: str,
        event_label: str,
    ) -> tuple[list[WorkerResult], list[WorkerAssignment]]:
        results: list[WorkerResult] = []
        assignments: list[WorkerAssignment] = []
        for todo_id in created_ids:
            if len(results) >= budget or self.outcome.is_solved:
                break
            todo = self.reader.get(todo_id)
            if todo is None or todo.status != TodoStatus.PENDING:
                continue
            worker, worker_name, reason = DeterministicClosurePolicy.select_worker(
                todo=todo, state=self.state, agent_directory=self.agent_directory
            )
            if worker is None:
                result = self.execution.block_assignment(
                    cycle=cycle,
                    todo=todo,
                    worker_name=worker_name or "deterministic-worker",
                    reason=reason,
                )
            else:
                assignments.append(
                    WorkerAssignment(
                        todo_id=todo.todo_id,
                        worker_name=worker_name,
                        rationale=assignment_rationale,
                    )
                )
                result = self.execution.run(cycle=cycle, todo=todo, worker=worker)
            self.execution.apply_result(
                cycle=cycle, todo=todo, result=result, event_label=event_label
            )
            results.append(result)
            self.events.checkpoint()
            if self.events.sync_background_flags(cycle, wait_s=0.2):
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                break
        return (results, assignments)

    def execute_flag_validation(
        self, *, cycle: int, todos: list[TodoItem]
    ) -> tuple[list[WorkerResult], list[WorkerAssignment]]:
        results: list[WorkerResult] = []
        assignments: list[WorkerAssignment] = []
        for todo in todos:
            if self.outcome.is_solved:
                break
            worker, reason = self.agent_directory.select(
                "flag-worker", todo, self.state
            )
            if worker is None:
                result = self.execution.block_assignment(
                    cycle=cycle, todo=todo, worker_name="flag-worker", reason=reason
                )
            else:
                assignments.append(
                    WorkerAssignment(
                        todo_id=todo.todo_id,
                        worker_name="flag-worker",
                        rationale="final validation pass",
                    )
                )
                result = self.execution.run(cycle=cycle, todo=todo, worker=worker)
            self.execution.apply_result(
                cycle=cycle, todo=todo, result=result, event_label="final validation"
            )
            results.append(result)
            self.events.checkpoint()
            if self.outcome.is_solved:
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                break
        return (results, assignments)
