"""Worker assignment execution and result application."""

from __future__ import annotations
import logging
import traceback
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.logging_utils import get_logger
from killchain_docker.orchestrator.agent_lifecycle import AgentLifecycle
import killchain_docker.orchestrator.runtime_events as runtime_events
from killchain_docker.orchestrator.round_result_signals import is_hollow_result
import killchain_docker.orchestrator.runtime_tasks as runtime_tasks
from killchain_docker.orchestrator.todo_status_commands import TodoStatusCommands
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.state.worker_results import WorkerResultApplier
from killchain_docker.workers.worker_agent import WorkerAgent

LOGGER = get_logger(__name__)


class AssignmentExecutionController:
    """Runs one routed worker assignment through a consistent lifecycle."""

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
        TodoStatusCommands(self.state).block(todo, reason, touch=False)
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
