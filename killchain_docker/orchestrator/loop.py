"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations
from collections.abc import Callable, Iterable
from killchain_docker.logging_utils import get_logger
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.dispatch_controller import DispatchCycleController
from killchain_docker.orchestrator.dispatch_rounds import DispatchRoundController
from killchain_docker.orchestrator.empty_dispatch import EmptyDispatchController
from killchain_docker.orchestrator.background_flags import (
    BackgroundFlagSolved,
    BackgroundFlagValidationController,
)
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.orchestrator.todo_queue_writer import TodoQueueWriter
from killchain_docker.orchestrator.todo_status_commands import TodoStatusCommands
from killchain_docker.orchestrator.assignment_execution import (
    AssignmentExecutionController,
)
from killchain_docker.orchestrator.closure_controller import ClosureExecutionController
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.routed_execution import (
    RoutedAssignmentExecutionController,
)
from killchain_docker.orchestrator.round_completion import (
    RoutedRoundCompletionController,
)
from killchain_docker.orchestrator.run_cycle_gate import RunCycleController
from killchain_docker.orchestrator.run_finalization import RunFinalizationController
from killchain_docker.orchestrator.run_lifecycle import RunLifecycleController
from killchain_docker.orchestrator.run_progress import RunProgressController
from killchain_docker.orchestrator.run_termination import RunTerminationController
from killchain_docker.orchestrator.planning.cycle_controller import (
    PlanningCycleController,
)
from killchain_docker.orchestrator.planning.queue_refresh import (
    PlanningRefreshController,
)
from killchain_docker.orchestrator.runtime_tasks import RuntimeTaskRegistry
from killchain_docker.orchestrator.planning.schemas import PlannerAgent
from killchain_docker.orchestrator.router import RouterAgent
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.run_state import RunState
from killchain_docker.workers.worker_agent import WorkerAgent

LOGGER = get_logger(__name__)


class Orchestrator:
    """Run the planner-router-worker loop for one assessment."""

    MAX_CONSECUTIVE_EMPTY_ROUNDS = 4
    FORCED_PIVOT_THRESHOLD = 5
    MAX_TRANSIENT_SKIPS = RunTerminationController.DEFAULT_MAX_TRANSIENT_SKIPS
    ROUTE_MAX_ASSIGNMENTS = 5

    def __init__(
        self,
        state: RunState,
        workers: Iterable[WorkerAgent],
        *,
        planner: PlannerAgent | None = None,
        router: RouterAgent | None = None,
        emit: Callable[[str], None] = LOGGER.info,
        checkpoint_callback: Callable[[RunState], None] | None = None,
    ) -> None:
        self.state = state
        if planner is None:
            raise LLMClientError(
                "Orchestrator requires an LLM planner; planner-less execution is disabled."
            )
        if router is None:
            raise LLMClientError(
                "Orchestrator requires a router; router-less execution is disabled."
            )
        self.workers = list(workers)
        self.agent_directory = AgentDirectory.from_workers(self.workers)
        self.todo_reader = TodoQueueReader(self.state)
        self.todo_writer = TodoQueueWriter(self.state)
        self.todo_commands = TodoStatusCommands(self.state)
        self.dispatch_rounds = DispatchRoundController(
            reader=self.todo_reader,
            commands=self.todo_commands,
            max_consecutive_empty_rounds=self.MAX_CONSECUTIVE_EMPTY_ROUNDS,
        )
        self.runtime_tasks = RuntimeTaskRegistry()
        self.planner = planner
        self.router = router
        self.emit = emit
        self.checkpoint_callback = checkpoint_callback
        self._journal = RunJournal(self.state)
        self._background_flags = BackgroundFlagValidationController(
            state=self.state,
            workers=self.workers,
            emit=self.emit,
            checkpoint=self._checkpoint,
        )
        self._events = RuntimeEventController(
            state=self.state,
            emit=self.emit,
            checkpoint=self._checkpoint,
            background_flags=self._background_flags,
        )
        self._termination_controller = RunTerminationController(
            self.state,
            events=self._events,
            max_transient_skips=self.MAX_TRANSIENT_SKIPS,
        )
        self._cycle_controller = RunCycleController(
            state=self.state, events=self._events
        )
        self._lifecycle_controller = RunLifecycleController(
            state=self.state,
            commands=self.todo_commands,
            events=self._events,
            journal=self._journal,
            termination=self._termination_controller,
            background_flags=self._background_flags,
        )
        self._progress_controller = RunProgressController(
            state=self.state,
            events=self._events,
            threshold=self.FORCED_PIVOT_THRESHOLD,
            journal=self._journal,
        )
        self._execution_controller = AssignmentExecutionController(
            state=self.state,
            lifecycle=self.agent_directory.lifecycle,
            registry=self.runtime_tasks,
            events=self._events,
            passthrough_exceptions=(BackgroundFlagSolved,),
            logger=LOGGER,
        )
        self._closure_controller = ClosureExecutionController(
            state=self.state,
            todo_reader=self.todo_reader,
            todo_writer=self.todo_writer,
            agent_directory=self.agent_directory,
            execution=self._execution_controller,
            events=self._events,
        )
        self._routed_execution_controller = RoutedAssignmentExecutionController(
            state=self.state,
            todo_reader=self.todo_reader,
            agent_directory=self.agent_directory,
            execution=self._execution_controller,
            termination=self._termination_controller,
            transient_error_skipper=self._termination_controller.skip_transient_llm_error,
            journal=self._journal,
        )
        self._finalization_controller = RunFinalizationController(
            state=self.state,
            events=self._events,
            closure=self._closure_controller,
            termination=self._termination_controller,
        )
        self._planning_refresh = PlanningRefreshController(
            state=self.state,
            planner=self.planner,
            writer=self.todo_writer,
            journal=self._journal,
            emit=self.emit,
        )
        self._planning_cycle_controller = PlanningCycleController(
            state=self.state,
            reader=self.todo_reader,
            refresh=self._planning_refresh,
            events=self._events,
            termination=self._termination_controller,
        )
        self._empty_dispatch_controller = EmptyDispatchController(
            rounds=self.dispatch_rounds, events=self._events
        )
        self._round_completion_controller = RoutedRoundCompletionController(
            state=self.state,
            closure=self._closure_controller,
            termination=self._termination_controller,
            progress=self._progress_controller,
            journal=self._journal,
            router=self.router,
            planner=self.planner,
            route_assignment_budget=lambda: self.ROUTE_MAX_ASSIGNMENTS,
        )
        self._dispatch_cycle_controller = DispatchCycleController(
            state=self.state,
            router=self.router,
            agent_directory=self.agent_directory,
            events=self._events,
            termination=self._termination_controller,
            empty_dispatch=self._empty_dispatch_controller,
            routed_execution=self._routed_execution_controller,
            round_completion=self._round_completion_controller,
            assignment_budget=lambda: self.ROUTE_MAX_ASSIGNMENTS,
        )

    def _checkpoint(self) -> None:
        if self.checkpoint_callback is None:
            return
        try:
            self.checkpoint_callback(self.state)
        except Exception as exc:
            LOGGER.exception(
                "checkpoint callback failed", extra={"run_id": self.state.run_id}
            )
            self.emit(
                f"[checkpoint] failed to persist state: {type(exc).__name__}: {exc}"
            )

    def run(self, max_cycles: int = 10) -> RunState:
        max_cycles_exhausted = True
        current_cycle = 0
        self._lifecycle_controller.start()
        try:
            for cycle in range(1, max_cycles + 1):
                current_cycle = cycle
                cycle_start = self._cycle_controller.begin(cycle=cycle)
                if cycle_start.halt_run:
                    max_cycles_exhausted = False
                    break
                planning = self._planning_cycle_controller.plan(cycle=cycle)
                if planning.retry_cycle:
                    continue
                if planning.halt_run:
                    max_cycles_exhausted = False
                    break
                dispatch = self._dispatch_cycle_controller.dispatch(
                    cycle=cycle, planner_summary=planning.summary
                )
                if dispatch.retry_cycle:
                    continue
                if dispatch.halt_run:
                    max_cycles_exhausted = False
                    break
        except LLMClientError as exc:
            self._lifecycle_controller.handle_uncaught_llm_error(
                cycle=current_cycle, exc=exc
            )
            max_cycles_exhausted = False
            raise
        except BackgroundFlagSolved:
            self._lifecycle_controller.handle_background_flag_solved(
                cycle=current_cycle
            )
            max_cycles_exhausted = False
        except (KeyboardInterrupt, SystemExit) as exc:
            self._lifecycle_controller.handle_interrupt(exc)
        finally:
            self._lifecycle_controller.stop_background()
        self._finalization_controller.finalize(
            current_cycle=current_cycle,
            max_cycles_exhausted=max_cycles_exhausted,
            planner=self.planner,
        )
        return self.state
