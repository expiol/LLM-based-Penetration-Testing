"""Round recording for deterministic closure passes."""

from __future__ import annotations

from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import (
    RouterRound,
    RouterRoundSummary,
    WorkerAssignment,
    WorkerResult,
)


class ClosureRoundRecorder:
    """Write synthetic router rounds for closure-only execution."""

    def __init__(
        self, *, state: RunState, journal: RunJournal, events: RuntimeEventController
    ) -> None:
        self.state = state
        self.journal = journal
        self.events = events

    def record(
        self,
        *,
        cycle: int,
        planner_summary: str,
        assignments: list[WorkerAssignment],
        results: list[WorkerResult],
    ) -> None:
        self.journal.round(
            RouterRound(
                cycle=cycle,
                planner_summary=planner_summary,
                assignments=assignments,
                results=results,
                summary=RouterRoundSummary(
                    summary="; ".join((result.summary for result in results)),
                    direct_results=[result.summary for result in results],
                ),
            )
        )
        RunStateMaintenance(self.state).touch()
        self.events.checkpoint()
