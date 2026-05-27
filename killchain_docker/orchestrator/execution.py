"""Unified worker execution: run one assignment or a batch."""

from __future__ import annotations
import logging
import traceback
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.logging_utils import get_logger
from killchain_docker.orchestrator.agent_lifecycle import AgentLifecycle
from killchain_docker.orchestrator.progress.result_signals import is_hollow_result
import killchain_docker.orchestrator.runtime_events as runtime_events
import killchain_docker.orchestrator.runtime_tasks as runtime_tasks
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    TodoItem,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
)
from killchain_docker.state.worker_results import WorkerResultApplier
from killchain_docker.workers.runtime.agent import WorkerAgent

LOGGER = get_logger(__name__)


WorkerSelector = Callable[[TodoItem], tuple[WorkerAgent | None, str, str]]
RationaleProvider = Callable[[TodoItem], str]


@dataclass(frozen=True)
class LLMErrorOutcome:
    """Action requested by a transient_llm handler after an LLM error."""

    skip_cycle: bool = False
    halt_run: bool = False
    fallback_result: WorkerResult | None = None

    @property
    def stop_batch(self) -> bool:
        return self.skip_cycle or self.halt_run

    @property
    def reraise(self) -> bool:
        return (
            not self.skip_cycle
            and not self.halt_run
            and self.fallback_result is None
        )


@dataclass
class TransientLLMHandling:
    """Pluggable LLM-error policy used during a worker run.

    Closure paths use the default (re-raise everything). The routed path
    supplies a concrete handler that delegates to RunTerminationController.
    """

    handle: Callable[[int, TodoItem, WorkerAgent, LLMClientError], LLMErrorOutcome] = (
        lambda _cycle, _todo, _worker, _exc: LLMErrorOutcome()
    )
    note_success: Callable[[WorkerAgent], None] = lambda _worker: None


PROPAGATE_LLM_ERROR = TransientLLMHandling()


@dataclass(frozen=True)
class BatchExecutionOutcome:
    """Flow signals collected after running one batch of assignments."""

    results: list[WorkerResult] = field(default_factory=list)
    executed_assignments: list[WorkerAssignment] = field(default_factory=list)
    solved: bool = False
    transient_skip: bool = False
    terminal_error: bool = False

    @property
    def stop_round(self) -> bool:
        return self.solved or self.transient_skip or self.terminal_error


class Execution:
    """Run one or many worker assignments through a consistent lifecycle."""

    def __init__(
        self,
        *,
        state: RunState,
        lifecycle: AgentLifecycle,
        registry: runtime_tasks.RuntimeTaskRegistry,
        events: runtime_events.RuntimeEventController,
        passthrough_exceptions: tuple[type[BaseException], ...] = (),
        logger: logging.Logger | None = None,
    ) -> None:
        self.state = state
        self.lifecycle = lifecycle
        self.registry = registry
        self.events = events
        self.result_applier = WorkerResultApplier(state)
        self.assignment_lifecycle = runtime_tasks.AssignmentLifecycleController(
            state=state, lifecycle=lifecycle, registry=registry
        )
        self.passthrough_exceptions = passthrough_exceptions
        self.logger = logger or LOGGER
        self.outcome = RunOutcomeStore(state)

    def run(self, *, cycle: int, todo: TodoItem, worker: WorkerAgent) -> WorkerResult:
        runtime_task = self.assignment_lifecycle.begin(
            cycle=cycle, todo=todo, worker=worker
        )
        self.events.checkpoint_activity(
            f"[cycle {cycle}] dispatch {todo.todo_id} -> {worker.name}",
            event_type="dispatch",
            **self.events.todo_context(cycle, todo, worker=worker.name),
        )
        previous_callback = worker.progress_callback
        previous_candidate_callback = worker.flag_candidate_callback
        worker.progress_callback = lambda state, task, message: (
            self.events.worker_progress(cycle, state, task, message)
        )
        worker.flag_candidate_callback = lambda state, task, candidates: (
            self.events.worker_flag_candidates(cycle, state, task, candidates)
        )
        try:
            result = worker.run(todo, self.state)
            self.assignment_lifecycle.complete(
                worker=worker, runtime_task=runtime_task, result=result
            )
            return result
        except LLMClientError as exc:
            if exc.transient:
                self.assignment_lifecycle.transient_interrupt(
                    todo=todo, worker=worker, runtime_task=runtime_task, reason=str(exc)
                )
                raise
            self.assignment_lifecycle.fail(
                worker=worker, runtime_task=runtime_task, error=str(exc)
            )
            raise
        except self.passthrough_exceptions:
            self.assignment_lifecycle.interrupt(
                worker=worker,
                runtime_task=runtime_task,
                reason="background_flag_validated",
            )
            raise
        except Exception as exc:
            tb_text = traceback.format_exc(limit=20)
            self.logger.exception(
                "worker execution failed",
                extra={
                    "run_id": self.state.run_id,
                    "cycle": cycle,
                    "todo_id": todo.todo_id,
                    "worker": worker.name,
                },
            )
            self.events.emit(
                f"[cycle {cycle}] UNHANDLED EXCEPTION in {worker.name} while executing {todo.todo_id}: {type(exc).__name__}: {exc}",
                event_type="worker_error",
                **self.events.todo_context(cycle, todo, worker=worker.name),
            )
            self.assignment_lifecycle.fail(
                worker=worker, runtime_task=runtime_task, error=str(exc)
            )
            return WorkerResult(
                todo_id=todo.todo_id,
                worker_name=worker.name,
                success=False,
                summary=f"{worker.name} raised {type(exc).__name__}: {exc}",
                error=tb_text,
                retryable=False,
            )
        finally:
            worker.progress_callback = previous_callback
            worker.flag_candidate_callback = previous_candidate_callback

    def apply_result(
        self,
        *,
        cycle: int,
        todo: TodoItem,
        result: WorkerResult,
        event_label: str | None = None,
    ) -> WorkerResult:
        """Apply worker output to state and emit the runtime result event."""
        if is_hollow_result(result):
            result.partial = True
            result.partial_reason = (
                result.partial_reason
                or "worker reported success but produced no meaningful output"
            )
            self.events.emit(
                f"[cycle {cycle}] hollow result downgraded to PARTIAL: {todo.todo_id}",
                event_type="worker_result_partial",
                **self.events.todo_context(cycle, todo, worker=result.worker_name),
            )
        self.result_applier.apply(result)
        status_tag = (
            "PARTIAL" if result.partial else "ok" if result.success else "FAILED"
        )
        if event_label:
            message = f"[cycle {cycle}] {event_label} {status_tag} {todo.todo_id}: {result.summary}"
        else:
            message = f"[cycle {cycle}] {status_tag} {todo.todo_id}: {result.summary}"
        self.events.emit(
            message,
            event_type="worker_result",
            **self.events.todo_context(cycle, todo, worker=result.worker_name),
            result_success=result.success,
            result_partial=result.partial,
        )
        return result

    def block_assignment(
        self, *, cycle: int, todo: TodoItem, worker_name: str, reason: str
    ) -> WorkerResult:
        """Mark an unrunnable assignment blocked and return its result record."""
        TodoQueue(self.state).block(todo, reason, touch=False)
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name=worker_name,
            success=False,
            summary=f"Assignment blocked: {reason}",
            error=reason,
            retryable=False,
        )
        self.events.emit(
            f"[cycle {cycle}] blocked {todo.todo_id}: {reason}",
            event_type="worker_blocked",
            **self.events.todo_context(cycle, todo, worker=worker_name),
        )
        return result

    def run_assignments(
        self,
        *,
        cycle: int,
        todos: list[TodoItem],
        select_worker: WorkerSelector,
        rationale: RationaleProvider | str,
        event_label: str | None,
        transient_llm: TransientLLMHandling = PROPAGATE_LLM_ERROR,
        budget: int | None = None,
        concurrent: bool = False,
    ) -> BatchExecutionOutcome:
        """Run a batch of todos, selecting workers via ``select_worker``.

        ``rationale`` may be a static string or a callable producing one
        per-todo. ``budget`` caps result count when provided. ``concurrent``
        runs the worker step in a thread pool while the per-iteration
        bookkeeping (apply_result, checkpoint, solved-detection) stays
        sequential to keep state writes deterministic.
        """
        rationale_for: RationaleProvider = (
            (lambda _todo: rationale) if isinstance(rationale, str) else rationale
        )
        results: list[WorkerResult] = []
        executed_assignments: list[WorkerAssignment] = []

        if concurrent and len(todos) > 1:
            return self._run_concurrent_batch(
                cycle=cycle,
                todos=todos,
                select_worker=select_worker,
                rationale_for=rationale_for,
                event_label=event_label,
                transient_llm=transient_llm,
                results=results,
                executed_assignments=executed_assignments,
            )

        for todo in todos:
            if budget is not None and len(results) >= budget:
                break
            if self.outcome.is_solved:
                break
            if todo.status != TodoStatus.PENDING:
                continue
            worker, worker_name, reason = select_worker(todo)
            if worker is None:
                results.append(
                    self.block_assignment(
                        cycle=cycle,
                        todo=todo,
                        worker_name=worker_name or "deterministic-worker",
                        reason=reason,
                    )
                )
                continue
            executed_assignments.append(
                WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name=worker_name,
                    rationale=rationale_for(todo),
                )
            )
            try:
                result = self.run(cycle=cycle, todo=todo, worker=worker)
            except LLMClientError as exc:
                outcome = transient_llm.handle(cycle, todo, worker, exc)
                if outcome.skip_cycle:
                    return BatchExecutionOutcome(
                        results=results,
                        executed_assignments=executed_assignments,
                        transient_skip=True,
                    )
                if outcome.halt_run:
                    return BatchExecutionOutcome(
                        results=results,
                        executed_assignments=executed_assignments,
                        terminal_error=True,
                    )
                if outcome.fallback_result is None:
                    raise
                result = outcome.fallback_result
            else:
                transient_llm.note_success(worker)
            self.apply_result(
                cycle=cycle, todo=todo, result=result, event_label=event_label
            )
            results.append(result)
            self.events.checkpoint()
            if self.events.sync_background_flags(cycle, wait_s=0.2):
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                return BatchExecutionOutcome(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
            if self.outcome.is_solved:
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                return BatchExecutionOutcome(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
        return BatchExecutionOutcome(
            results=results,
            executed_assignments=executed_assignments,
            solved=self.outcome.is_solved,
        )

    def _run_concurrent_batch(
        self,
        *,
        cycle: int,
        todos: list[TodoItem],
        select_worker: WorkerSelector,
        rationale_for: RationaleProvider,
        event_label: str | None,
        transient_llm: TransientLLMHandling,
        results: list[WorkerResult],
        executed_assignments: list[WorkerAssignment],
    ) -> BatchExecutionOutcome:
        pending: list[tuple[TodoItem, WorkerAgent, str]] = []
        for todo in todos:
            if todo.status != TodoStatus.PENDING:
                continue
            worker, worker_name, reason = select_worker(todo)
            if worker is None:
                results.append(
                    self.block_assignment(
                        cycle=cycle,
                        todo=todo,
                        worker_name=worker_name or "deterministic-worker",
                        reason=reason,
                    )
                )
                continue
            pending.append((todo, worker, worker_name))
        if not pending:
            return BatchExecutionOutcome(
                results=results,
                executed_assignments=executed_assignments,
                solved=self.outcome.is_solved,
            )
        self.events.emit(
            f"[cycle {cycle}] concurrent safe assignment batch size={len(pending)}",
            event_type="worker_concurrent_batch",
        )
        completed: dict[str, WorkerResult] = {}
        with ThreadPoolExecutor(max_workers=len(pending)) as pool:
            future_map = {
                pool.submit(self.run, cycle=cycle, todo=todo, worker=worker): (
                    todo,
                    worker,
                    worker_name,
                )
                for todo, worker, worker_name in pending
            }
            for future in as_completed(future_map):
                todo, worker, worker_name = future_map[future]
                executed_assignments.append(
                    WorkerAssignment(
                        todo_id=todo.todo_id,
                        worker_name=worker_name,
                        rationale=rationale_for(todo),
                    )
                )
                try:
                    completed[todo.todo_id] = future.result()
                except LLMClientError as exc:
                    outcome = transient_llm.handle(cycle, todo, worker, exc)
                    if outcome.skip_cycle:
                        return BatchExecutionOutcome(
                            results=results,
                            executed_assignments=executed_assignments,
                            transient_skip=True,
                        )
                    if outcome.halt_run:
                        return BatchExecutionOutcome(
                            results=results,
                            executed_assignments=executed_assignments,
                            terminal_error=True,
                        )
                    if outcome.fallback_result is None:
                        raise
                    completed[todo.todo_id] = outcome.fallback_result
                else:
                    transient_llm.note_success(worker)
        for todo, _worker, _worker_name in pending:
            result = completed.get(todo.todo_id)
            if result is None:
                continue
            self.apply_result(
                cycle=cycle, todo=todo, result=result, event_label=event_label
            )
            results.append(result)
            self.events.checkpoint()
            if self.events.sync_background_flags(cycle, wait_s=0.2):
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                return BatchExecutionOutcome(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
            if self.outcome.is_solved:
                self.events.emit(self.outcome.solved_message(cycle=cycle))
                return BatchExecutionOutcome(
                    results=results,
                    executed_assignments=executed_assignments,
                    solved=True,
                )
        return BatchExecutionOutcome(
            results=results,
            executed_assignments=executed_assignments,
            solved=self.outcome.is_solved,
        )


def routed_transient_llm_handling(
    *,
    termination,
    events: runtime_events.RuntimeEventController,
    journal: RunJournal | None = None,
) -> TransientLLMHandling:
    """Build the routed-path LLM error policy.

    Skips transient errors while the skip budget remains; once the budget
    is exhausted, halts the run. Non-transient errors fall back to a
    typed worker_llm_error WorkerResult so the cycle can proceed.
    """
    del journal

    def handle(
        cycle: int, todo: TodoItem, worker: WorkerAgent, exc: LLMClientError
    ) -> LLMErrorOutcome:
        if termination.skip_transient_llm_error(cycle, worker.name, exc):
            return LLMErrorOutcome(skip_cycle=True)
        if exc.transient:
            termination.interrupt_todo_after_transient_budget(
                cycle, worker.name, exc, todo=todo
            )
            events.checkpoint()
            return LLMErrorOutcome(skip_cycle=True)
        events.emit(
            f"[cycle {cycle}] worker LLM error in {worker.name} - marking {todo.todo_id} failed and continuing",
            event_type="worker_llm_error",
            **events.todo_context(cycle, todo, worker=worker.name),
        )
        return LLMErrorOutcome(
            fallback_result=termination.worker_llm_error_result(
                cycle=cycle, todo=todo, worker_name=worker.name, exc=exc
            )
        )

    def note_success(worker: WorkerAgent) -> None:
        termination.note_successful_step(worker.name)

    return TransientLLMHandling(handle=handle, note_success=note_success)
