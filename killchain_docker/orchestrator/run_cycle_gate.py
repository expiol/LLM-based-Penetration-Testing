"""Cycle entry gates for the orchestration loop."""

from __future__ import annotations

from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.runtime_results import RunCycleGateResult
from killchain_docker.state.common import utc_now
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState


class RunCycleController:
    """Owns per-cycle entry gates before planning and dispatch."""

    def __init__(self, *, state: RunState, events: RuntimeEventController) -> None:
        self.state = state
        self.events = events
        self.outcome = RunOutcomeStore(state)

    def begin(self, *, cycle: int) -> RunCycleGateResult:
        if self.events.sync_background_flags(cycle):
            self.events.emit(
                f"[cycle {cycle}] background flag validation solved - halting run"
            )
            return RunCycleGateResult(halt_run=True)
        if self.outcome.is_solved:
            self.events.emit(f"[cycle {cycle}] validated flag found - halting run")
            return RunCycleGateResult(halt_run=True)
        self.outcome.cycle_started(at=utc_now(), touch=False)
        return RunCycleGateResult()
