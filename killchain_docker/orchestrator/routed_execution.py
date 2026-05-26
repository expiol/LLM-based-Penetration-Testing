"""Execution for router-selected assignments."""

from __future__ import annotations
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.assignment_batches import (
    assignment_execution_batches,
)
from killchain_docker.orchestrator.assignment_execution import (
    AssignmentExecutionController,
)
from killchain_docker.orchestrator.runtime_results import RoutedAssignmentBatchResult
from killchain_docker.orchestrator.run_termination import RunTerminationController
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoStatus, WorkerAssignment, WorkerResult
from killchain_docker.state.outcome import RunOutcomeStore


class RoutedAssignmentExecutionController:
    """Executes router-selected worker assignments for one cycle."""

    def __init__(
        self,
        *,
        state: RunState,
        todo_reader: TodoQueueReader,
        agent_directory: AgentDirectory,
        execution: AssignmentExecutionController,
        termination: RunTerminationController,
        transient_error_skipper: Callable[[int, str, LLMClientError], bool],
        journal: RunJournal,
    ) -> None:
        self.state = state
        self.todo_reader = todo_reader
        self.agent_directory = agent_directory
        self.execution = execution
        self.termination = termination
        self.transient_error_skipper = transient_error_skipper
        self.journal = journal
        self.outcome = RunOutcomeStore(state)

    def execute(
        self, *, cycle: int, assignments: list[WorkerAssignment]
    ) -> RoutedAssignmentBatchResult:
        results: list[WorkerResult] = []
        executed_assignments: list[WorkerAssignment] = []
        todos_by_id = {
            assignment.todo_id: todo
            for assignment in assignments
            if (todo := self.todo_reader.get(assignment.todo_id)) is not None
        }
        for batch in assignment_execution_batches(assignments, todos_by_id):
            if self.outcome.is_solved:
                break
            if batch.concurrent and len(batch.assignments) > 1:
                batch_result = self._execute_concurrent_batch(
                    cycle=cycle,
                    assignments=batch.assignments,
                    results=results,
                    executed_assignments=executed_assignments,
                )
                if batch_result is not None:
                    return batch_result
                continue
            batch_result = self._execute_sequential_batch(
                cycle=cycle,
                assignments=batch.assignments,
                results=results,
                executed_assignments=executed_assignments,
            )
            if batch_result is not None:
                return batch_result
        return RoutedAssignmentBatchResult(
            results=results,
            executed_assignments=executed_assignments,
            solved=self.outcome.is_solved,
        )

    def _execute_sequential_batch(
        self,
        *,
        cycle: int,
        assignments: list[WorkerAssignment],
        results: list[WorkerResult],
        executed_assignments: list[WorkerAssignment],
    ) -> RoutedAssignmentBatchResult | None:
        for assignment in assignments:
            todo = self.todo_reader.get(assignment.todo_id)
            if todo is None:
                self.journal.orchestration_note(
                    f"cycle {cycle}: assignment referenced unknown todo {assignment.todo_id}"
                )
                continue
            if todo.status != TodoStatus.PENDING:
                continue
            worker, reason = self.agent_directory.select(
                assignment.worker_name, todo, self.state
            )
            if worker is None:
                results.append(
                    self.execution.block_assignment(
                        cycle=cycle,
                        todo=todo,
                        worker_name=assignment.worker_name,
                        reason=reason,
                    )
                )
                continue
            executed_assignments.append(assignment)
            try:
                result = self.execution.run(cycle=cycle, todo=todo, worker=worker)
            except LLMClientError as exc:
                if self.transient_error_skipper(cycle, worker.name, exc):
                    return RoutedAssignmentBatchResult(
                        results=results,
                        executed_assignments=executed_assignments,
                        transient_skip=True,
                    )
                if exc.transient:
                    self.termination.halt_after_transient_llm_error(
                        cycle, worker.name, exc, todo=todo
                    )
                    self.execution.events.checkpoint()
                    return RoutedAssignmentBatchResult(
                        results=results,
                        executed_assignments=executed_assignments,
                        terminal_error=True,
                    )
                self.execution.events.emit(
                    f"[cycle {cycle}] worker LLM error in {worker.name} - marking {todo.todo_id} failed and continuing",
                    event_type="worker_llm_error",
                    **self.execution.events.todo_context(
                        cycle, todo, worker=worker.name
                    ),
                )
                result = self.termination.worker_llm_error_result(
                    cycle=cycle, todo=todo, worker_name=worker.name, exc=exc
                )
            self.execution.apply_result(cycle=cycle, todo=todo, result=result)
            results.append(result)
            self.execution.events.checkpoint()
            if self.execution.events.sync_background_flags(cycle, wait_s=0.2):
                self.execution.events.emit(self.outcome.solved_message(cycle=cycle))
                return RoutedAssignmentBatchResult(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
            if self.outcome.is_solved:
                self.execution.events.emit(self.outcome.solved_message(cycle=cycle))
                return RoutedAssignmentBatchResult(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
        return None

    def _execute_concurrent_batch(
        self,
        *,
        cycle: int,
        assignments: list[WorkerAssignment],
        results: list[WorkerResult],
        executed_assignments: list[WorkerAssignment],
    ) -> RoutedAssignmentBatchResult | None:
        pending: list[tuple[WorkerAssignment, TodoItem, object]] = []
        for assignment in assignments:
            todo = self.todo_reader.get(assignment.todo_id)
            if todo is None:
                self.journal.orchestration_note(
                    f"cycle {cycle}: assignment referenced unknown todo {assignment.todo_id}"
                )
                continue
            if todo.status != TodoStatus.PENDING:
                continue
            worker, reason = self.agent_directory.select(
                assignment.worker_name, todo, self.state
            )
            if worker is None:
                results.append(
                    self.execution.block_assignment(
                        cycle=cycle,
                        todo=todo,
                        worker_name=assignment.worker_name,
                        reason=reason,
                    )
                )
                continue
            pending.append((assignment, todo, worker))
        if not pending:
            return None
        self.execution.events.emit(
            f"[cycle {cycle}] concurrent safe assignment batch size={len(pending)}",
            event_type="worker_concurrent_batch",
        )
        by_todo_id: dict[str, tuple[WorkerAssignment, TodoItem, WorkerResult]] = {}
        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            future_map = {
                pool.submit(
                    self.execution.run, cycle=cycle, todo=todo, worker=worker
                ): (
                    assignment,
                    todo,
                    worker,
                )
                for assignment, todo, worker in pending
            }
            for future in as_completed(future_map):
                assignment, todo, worker = future_map[future]
                executed_assignments.append(assignment)
                try:
                    result = future.result()
                except LLMClientError as exc:
                    if self.transient_error_skipper(cycle, worker.name, exc):
                        return RoutedAssignmentBatchResult(
                            results=results,
                            executed_assignments=executed_assignments,
                            transient_skip=True,
                        )
                    if exc.transient:
                        self.termination.halt_after_transient_llm_error(
                            cycle, worker.name, exc, todo=todo
                        )
                        self.execution.events.checkpoint()
                        return RoutedAssignmentBatchResult(
                            results=results,
                            executed_assignments=executed_assignments,
                            terminal_error=True,
                        )
                    self.execution.events.emit(
                        f"[cycle {cycle}] worker LLM error in {worker.name} - marking {todo.todo_id} failed and continuing",
                        event_type="worker_llm_error",
                        **self.execution.events.todo_context(
                            cycle, todo, worker=worker.name
                        ),
                    )
                    result = self.termination.worker_llm_error_result(
                        cycle=cycle, todo=todo, worker_name=worker.name, exc=exc
                    )
                by_todo_id[todo.todo_id] = (assignment, todo, result)
        for _assignment, todo, _worker in pending:
            item = by_todo_id.get(todo.todo_id)
            if item is None:
                continue
            assignment, todo, result = item
            self.execution.apply_result(
                cycle=cycle,
                todo=todo,
                result=result,
                event_label="concurrent",
            )
            results.append(result)
            self.execution.events.checkpoint()
            if self.execution.events.sync_background_flags(cycle, wait_s=0.2):
                self.execution.events.emit(self.outcome.solved_message(cycle=cycle))
                return RoutedAssignmentBatchResult(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
            if self.outcome.is_solved:
                self.execution.events.emit(self.outcome.solved_message(cycle=cycle))
                return RoutedAssignmentBatchResult(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
        return None
