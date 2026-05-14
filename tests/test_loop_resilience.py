"""Tests for the planner-router-worker orchestrator loop."""

from __future__ import annotations

import unittest
from collections.abc import Iterable

from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning import PlannedTodo, PlannerDecision, TaskPlanner
from killchain_docker.state import (
    RouterDecision,
    RouterRoundSummary,
    RunState,
    RunStatus,
    TodoItem,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
)
from killchain_docker.workers.base import WorkerAgent


class _ScriptedPlanner(TaskPlanner):
    def __init__(self, scripts: Iterable[PlannerDecision]) -> None:
        self._scripts = list(scripts)
        self._cursor = 0

    def plan(self, state: RunState) -> PlannerDecision:
        del state
        if self._cursor < len(self._scripts):
            decision = self._scripts[self._cursor]
            self._cursor += 1
            return decision
        return PlannerDecision(summary="no more todos", todos=[], notes=[], stop_run=False)


class _ContextRouter:
    def route(self, state: RunState, *, worker_catalog, max_assignments: int) -> RouterDecision:
        del worker_catalog, max_assignments
        ready = state.ready_todos(limit=1)
        if not ready:
            return RouterDecision(rationale="empty")
        todo = ready[0]
        return RouterDecision(
            assignments=[
                WorkerAssignment(
                    todo_id=todo.todo_id,
                    worker_name=str(todo.context["worker_name"]),
                    rationale="test route",
                )
            ],
            rationale="test route",
        )

    def summarize_round(self, state: RunState, *, results: list[WorkerResult]) -> RouterRoundSummary:
        del state
        return RouterRoundSummary(
            summary="; ".join(result.summary for result in results),
            direct_results=[result.summary for result in results],
        )


class _RaisingWorker(WorkerAgent):
    name = "raising-worker"
    supported_task_types = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise LLMClientError("synthetic worker LLM failure", transient=False)


class _SuccessWorker(WorkerAgent):
    name = "success-worker"
    supported_task_types = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="ok",
        )


def _state() -> RunState:
    return RunState(
        objective="resilience smoke",
        authorized_scope=[],
        metadata={"challenge": {"name": "test", "category": "misc", "files": []}},
    )


class OrchestratorLoopTests(unittest.TestCase):
    def test_worker_llm_error_does_not_abort_next_cycle(self) -> None:
        events: list[str] = []
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Raise once",
                        context={"worker_name": "raising-worker"},
                        dedupe_key="raise-once",
                    )
                ],
            ),
            PlannerDecision(
                summary="cycle 2",
                todos=[
                    PlannedTodo(
                        goal="Succeed once",
                        context={"worker_name": "success-worker"},
                        dedupe_key="succeed-once",
                    )
                ],
            ),
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_RaisingWorker(), _SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )

        final_state = orchestrator.run(max_cycles=4)

        failing = next(todo for todo in final_state.todos if todo.dedupe_key == "raise-once")
        passing = next(todo for todo in final_state.todos if todo.dedupe_key == "succeed-once")
        self.assertEqual(failing.status, TodoStatus.FAILED)
        self.assertEqual(passing.status, TodoStatus.COMPLETED)
        self.assertIn(final_state.status, {RunStatus.COMPLETED, RunStatus.FAILED})
        self.assertEqual(len(final_state.rounds), 2)
        self.assertTrue(any("FAILED" in event for event in events))


if __name__ == "__main__":
    unittest.main()

