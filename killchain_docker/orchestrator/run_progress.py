"""Progress stagnation tracking and forced pivot injection."""

from __future__ import annotations

from killchain_docker.orchestrator.forced_pivot import forced_pivot_directive
from killchain_docker.orchestrator.round_progress_signals import (
    had_meaningful_progress,
)
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import WorkerResult


class RunProgressController:
    """Owns progress stagnation tracking and forced pivot injection."""

    def __init__(
        self,
        *,
        state: RunState,
        events: RuntimeEventController,
        threshold: int,
        journal: RunJournal | None = None,
    ) -> None:
        self.state = state
        self.events = events
        self.threshold = max(1, threshold)
        self.journal = journal or RunJournal(state)
        self.metadata = RunMetadataStore(state)
        self.rounds_without_progress = 0
        self.pivot_count = 0

    def observe_round(self, *, cycle: int, results: list[WorkerResult]) -> bool:
        """Update progress counters and inject a forced pivot if needed."""
        if had_meaningful_progress(results):
            self.rounds_without_progress = 0
            self.metadata.clear_forced_pivot()
            return False
        self.rounds_without_progress += 1
        if self.rounds_without_progress < self.threshold:
            return False
        self._inject_forced_pivot(cycle)
        return True

    def _inject_forced_pivot(self, cycle: int) -> None:
        self.pivot_count += 1
        self.rounds_without_progress = 0
        pivot_directive = forced_pivot_directive(
            self.state,
            pivot_number=self.pivot_count,
            cycle=cycle,
            threshold=self.threshold,
        )
        banned_families = list(pivot_directive.get("banned_families") or [])
        self.metadata.set_forced_pivot(pivot_directive)
        self.journal.orchestration_note(
            f"cycle {cycle}: forced pivot #{self.pivot_count} - banned families: {banned_families}"
        )
        self.events.emit(
            f"[cycle {cycle}] FORCED PIVOT #{self.pivot_count}: banning families {banned_families}"
        )
