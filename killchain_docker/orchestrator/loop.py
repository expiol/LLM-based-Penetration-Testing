"""Planner -> RouterAgent -> persona workers orchestration loop."""

from __future__ import annotations
from collections.abc import Callable, Iterable
from killchain_docker.logging_utils import get_logger
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.memory.persistence import DurableMemoryStore
from killchain_docker.orchestrator.dispatch.controller import DispatchCycleController
from killchain_docker.orchestrator.background_flags import (
    BackgroundFlagSolved,
    BackgroundFlagValidationController,
)
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.orchestrator.execution import (
    Execution,
    routed_transient_llm_handling,
)
from killchain_docker.orchestrator.closure.controller import ClosureExecutionController
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.progress.run_progress import RunProgressController
from killchain_docker.orchestrator.run_termination import RunTerminationController
from killchain_docker.orchestrator.planning.cycle_controller import (
    PlanningCycleController,
)
from killchain_docker.orchestrator.planning.queue_refresh import (
    PlanningRefreshController,
)
from killchain_docker.orchestrator.runtime_tasks import RuntimeTaskRegistry
from killchain_docker.orchestrator.planning.schemas import PlannerAgent
from killchain_docker.orchestrator.dispatch.router import RouterAgent
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.state.common import utc_now
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState
from killchain_docker.workers.runtime.agent import WorkerAgent

LOGGER = get_logger(__name__)


class Orchestrator:
    """Run the planner-router-worker loop for one assessment."""

    MAX_CONSECUTIVE_EMPTY_ROUNDS = 4
    FORCED_PIVOT_THRESHOLD = 5
    MAX_TRANSIENT_SKIPS = RunTerminationController.DEFAULT_MAX_TRANSIENT_SKIPS
    ROUTE_MAX_ASSIGNMENTS = 5
    FINAL_DETERMINISTIC_CLOSURE_PASSES = 2
    FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS = 8

    def __init__(
        self,
        state: RunState,
        workers: Iterable[WorkerAgent],
        *,
        planner: PlannerAgent | None = None,
        router: RouterAgent | None = None,
        emit: Callable[[str], None] = LOGGER.info,
        checkpoint_callback: Callable[[RunState], None] | None = None,
        durable_memory_store: DurableMemoryStore | None = None,
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
        self.todos = TodoQueue(self.state)
        self.runtime_tasks = RuntimeTaskRegistry()
        self.planner = planner
        self.router = router
        self.emit = emit
        self.durable_memory_store = durable_memory_store
        self.checkpoint_callback = checkpoint_callback
        self._journal = RunJournal(self.state)
        self._outcome = RunOutcomeStore(self.state)
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
        self._progress_controller = RunProgressController(
            state=self.state,
            events=self._events,
            threshold=self.FORCED_PIVOT_THRESHOLD,
            journal=self._journal,
        )
        self._execution_controller = Execution(
            state=self.state,
            lifecycle=self.agent_directory.lifecycle,
            registry=self.runtime_tasks,
            events=self._events,
            passthrough_exceptions=(BackgroundFlagSolved,),
            logger=LOGGER,
        )
        self._closure_controller = ClosureExecutionController(
            state=self.state,
            todos=self.todos,
            agent_directory=self.agent_directory,
            execution=self._execution_controller,
            events=self._events,
        )
        self._routed_transient_llm = routed_transient_llm_handling(
            termination=self._termination_controller,
            events=self._events,
            journal=self._journal,
        )
        self._planning_refresh = PlanningRefreshController(
            state=self.state,
            planner=self.planner,
            todos=self.todos,
            journal=self._journal,
            emit=self.emit,
        )
        self._planning_cycle_controller = PlanningCycleController(
            state=self.state,
            todos=self.todos,
            refresh=self._planning_refresh,
            events=self._events,
            termination=self._termination_controller,
        )
        self._dispatch_cycle_controller = DispatchCycleController(
            state=self.state,
            router=self.router,
            agent_directory=self.agent_directory,
            events=self._events,
            termination=self._termination_controller,
            execution=self._execution_controller,
            transient_llm=self._routed_transient_llm,
            closure=self._closure_controller,
            progress=self._progress_controller,
            planner=self.planner,
            assignment_budget=lambda: self.ROUTE_MAX_ASSIGNMENTS,
            max_consecutive_empty_rounds=self.MAX_CONSECUTIVE_EMPTY_ROUNDS,
            journal=self._journal,
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

    def _begin_cycle(self, *, cycle: int) -> bool:
        """Per-cycle entry gate. Return True if the run should halt."""
        if self._events.sync_background_flags(cycle):
            self._events.emit(
                f"[cycle {cycle}] background flag validation solved - halting run"
            )
            return True
        if self._outcome.is_solved:
            self._events.emit(f"[cycle {cycle}] validated flag found - halting run")
            return True
        self._outcome.cycle_started(at=utc_now(), touch=False)
        return False

    def _handle_uncaught_llm_error(self, *, cycle: int, exc: LLMClientError) -> None:
        if self._outcome.has_stop_reason("llm_error"):
            return
        self._events.emit(f"[cycle {cycle}] LLM error - aborting run")
        self._termination_controller.mark_llm_error(cycle, "runtime", exc)
        self._events.checkpoint()

    def _handle_interrupt(self, exc: KeyboardInterrupt | SystemExit) -> None:
        reason = f"run interrupted by {type(exc).__name__}"
        self.todos.interrupt_running(reason)
        self._outcome.interrupted("interrupted", touch=False)
        self._journal.orchestration_note(reason)
        self._events.emit(f"[interrupt] {reason}; marked running todos as interrupted")
        self._events.checkpoint()

    def _flush_durable_memory(self) -> None:
        """Persist any pending durable memory updates collected during the run."""
        if self.durable_memory_store is None:
            return
        pending = list(self.state.pending_durable_memory_updates)
        if not pending:
            return
        challenge = ChallengeProjection(self.state)
        try:
            self.durable_memory_store.apply_updates(
                pending,
                run_id=self.state.run_id,
                category=challenge.category_raw() or None,
                challenge=challenge.name(),
            )
        except Exception:
            LOGGER.exception(
                "failed to flush durable memory",
                extra={"run_id": self.state.run_id},
            )
            return
        self.state.pending_durable_memory_updates.clear()

    def _finalize(self, *, current_cycle: int, max_cycles_exhausted: bool) -> None:
        """Run final deterministic closure passes then apply terminal status rules."""
        exhausted = max_cycles_exhausted
        final_cycle = current_cycle + 1
        if exhausted and self._events.sync_background_flags(final_cycle, wait_s=0.2):
            exhausted = False
        if exhausted:
            ran_final_closure = (
                self._closure_controller.final_deterministic_evidence_pass(
                    cycle=final_cycle,
                    planner=self.planner,
                    max_passes=self.FINAL_DETERMINISTIC_CLOSURE_PASSES,
                    max_assignments=self.FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS,
                )
            )
            if ran_final_closure and self._outcome.is_solved:
                exhausted = False
        if exhausted and self._events.sync_background_flags(final_cycle, wait_s=0.2):
            exhausted = False
        if exhausted:
            ran_final_validation = self._closure_controller.final_flag_validation_pass(
                cycle=final_cycle,
            )
            if ran_final_validation and self._outcome.is_solved:
                exhausted = False
        self._termination_controller.finalize(max_cycles_exhausted=exhausted)
        self._flush_durable_memory()

    def run(self, max_cycles: int = 10) -> RunState:
        max_cycles_exhausted = True
        current_cycle = 0
        productive_cycles = 0
        cycle = 0
        self._outcome.start(touch=False)
        self._background_flags.start()
        try:
            while productive_cycles < max_cycles:
                cycle += 1
                current_cycle = cycle
                if self._begin_cycle(cycle=cycle):
                    max_cycles_exhausted = False
                    break
                planning = self._planning_cycle_controller.plan(cycle=cycle)
                if planning.halt_run:
                    max_cycles_exhausted = False
                    break
                if planning.retry_cycle:
                    if not planning.transient_skip:
                        productive_cycles += 1
                    continue
                dispatch = self._dispatch_cycle_controller.dispatch(
                    cycle=cycle, planner_summary=planning.summary
                )
                if dispatch.halt_run:
                    max_cycles_exhausted = False
                    break
                if dispatch.retry_cycle and dispatch.transient_skip:
                    continue
                productive_cycles += 1
        except LLMClientError as exc:
            self._handle_uncaught_llm_error(cycle=current_cycle, exc=exc)
            max_cycles_exhausted = False
            raise
        except BackgroundFlagSolved:
            self._events.emit(
                f"[cycle {current_cycle}] background flag validation solved - halting run"
            )
            max_cycles_exhausted = False
        except (KeyboardInterrupt, SystemExit) as exc:
            self._handle_interrupt(exc)
        finally:
            self._background_flags.stop()
        self._finalize(
            current_cycle=current_cycle,
            max_cycles_exhausted=max_cycles_exhausted,
        )
        return self.state
