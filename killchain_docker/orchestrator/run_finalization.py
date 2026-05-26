"""Post-loop deterministic closure and terminal finalization."""

from __future__ import annotations

from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.run_termination import RunTerminationController
from killchain_docker.state.outcome import RunOutcomeStore


class RunFinalizationController:
    """Owns post-loop closure passes and terminal run finalization."""

    DEFAULT_FINAL_DETERMINISTIC_CLOSURE_PASSES = 2
    DEFAULT_FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS = 8

    def __init__(
        self,
        *,
        state,
        events: RuntimeEventController,
        closure,
        termination: RunTerminationController,
        final_closure_passes: int = DEFAULT_FINAL_DETERMINISTIC_CLOSURE_PASSES,
        final_closure_assignments: int = DEFAULT_FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS,
    ) -> None:
        self.state = state
        self.events = events
        self.closure = closure
        self.termination = termination
        self.final_closure_passes = max(0, final_closure_passes)
        self.final_closure_assignments = max(0, final_closure_assignments)
        self.outcome = RunOutcomeStore(state)

    def finalize(
        self,
        *,
        current_cycle: int,
        max_cycles_exhausted: bool,
        planner: object,
    ) -> None:
        """Run final deterministic work before applying terminal status rules."""

        exhausted = max_cycles_exhausted
        final_cycle = current_cycle + 1
        if exhausted and self.events.sync_background_flags(final_cycle, wait_s=0.2):
            exhausted = False
        if exhausted:
            ran_final_closure = self.closure.final_deterministic_evidence_pass(
                cycle=final_cycle,
                planner=planner,
                max_passes=self.final_closure_passes,
                max_assignments=self.final_closure_assignments,
            )
            if ran_final_closure and self.outcome.is_solved:
                exhausted = False
        if exhausted and self.events.sync_background_flags(final_cycle, wait_s=0.2):
            exhausted = False
        if exhausted:
            ran_final_validation = self.closure.final_flag_validation_pass(
                cycle=final_cycle,
            )
            if ran_final_validation and self.outcome.is_solved:
                exhausted = False
        self.termination.finalize(max_cycles_exhausted=exhausted)
