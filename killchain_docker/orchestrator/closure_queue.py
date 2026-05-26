"""Queue helpers for deterministic closure planner decisions."""

from __future__ import annotations

from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.orchestrator.todo_queue_writer import TodoQueueWriter
from killchain_docker.state.journal import RunJournal


class ClosureQueue:
    """Persist closure todos and planner notes."""

    def __init__(self, *, writer: TodoQueueWriter, journal: RunJournal) -> None:
        self.writer = writer
        self.journal = journal

    def enqueue_decision(self, decision: PlannerDecision) -> tuple[int, int, list[str]]:
        report = self.writer.enqueue_planned(decision.todos)
        if decision.notes:
            self.journal.orchestration_notes(decision.notes)
        return (report.proposed, report.created, report.created_ids)
