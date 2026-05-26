"""Planner decision to live queue refresh."""

from __future__ import annotations

from collections.abc import Callable

from killchain_docker.orchestrator.planning.dependency_gate import (
    gate_planned_dependencies,
)
from killchain_docker.orchestrator.planning.refresh_results import (
    DETERMINISTIC_BACKLOG_SUMMARY,
    PlanningRefreshResult,
)
from killchain_docker.orchestrator.planning.schemas import PlannerAgent, PlannerDecision
from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.run_state import RunState


class PlanningRefreshController:
    """Owns planner decisions entering the live task queue."""

    def __init__(
        self,
        *,
        state: RunState,
        planner: PlannerAgent,
        todos: TodoQueue,
        journal: RunJournal,
        emit: Callable[[str], None],
    ) -> None:
        self.state = state
        self.planner = planner
        self.todos = todos
        self.journal = journal
        self.emit = emit

    def refresh(self, *, cycle: int) -> PlanningRefreshResult:
        decision = self.planner.plan(self.state)
        result = self._enqueue(decision)
        self.emit(
            f"[cycle {cycle}] plan: proposed={result.proposed} new={result.created} "
            f"deduped={result.deduped} stop_run={result.stop_run} - {result.summary[:200]}"
        )
        return result

    def refresh_deterministic_seeds(self, *, cycle: int) -> PlanningRefreshResult:
        merge = self._planner_merge()
        if merge is None:
            return PlanningRefreshResult(
                summary=DETERMINISTIC_BACKLOG_SUMMARY,
                proposed=0,
                created=0,
                created_ids=[],
                deterministic=True,
            )
        decision = merge(
            self.state,
            llm_decision=PlannerDecision(
                summary="Deterministic seed refresh while ready backlog exists.",
                todos=[],
                notes=["Skipped LLM planning because ready todo backlog exists."],
            ),
        )
        result = self._enqueue(decision, deterministic=True)
        if result.proposed or result.created:
            self.emit(
                f"[cycle {cycle}] deterministic seed refresh: proposed={result.proposed} "
                f"new={result.created} deduped={result.deduped}"
            )
        return result

    def _enqueue(
        self, decision: PlannerDecision, *, deterministic: bool = False
    ) -> PlanningRefreshResult:
        todos, dependency_notes = gate_planned_dependencies(decision.todos, self.state)
        report = self.todos.enqueue_planned(todos)
        notes = [*decision.notes, *dependency_notes]
        if notes:
            self.journal.orchestration_notes(notes)
        return PlanningRefreshResult(
            summary=decision.summary or "(no summary)",
            proposed=len(decision.todos),
            created=report.created,
            created_ids=report.created_ids,
            stop_run=decision.stop_run,
            deterministic=deterministic,
        )

    def _planner_merge(self) -> Callable[..., PlannerDecision] | None:
        pipeline = getattr(self.planner, "pipeline", None)
        merge = getattr(pipeline, "merge", None)
        return merge if callable(merge) else None
