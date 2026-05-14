"""Tests for the planner-router-worker orchestrator loop."""

from __future__ import annotations

import unittest
from collections.abc import Iterable

from killchain_docker.llm import LLMClientError
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning import PlannerAgent, PlannedTodo, PlannerDecision
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


class _ScriptedPlanner(PlannerAgent):
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


class _UnknownWorkerRouter:
    def route(self, state: RunState, *, worker_catalog, max_assignments: int) -> RouterDecision:
        del worker_catalog, max_assignments
        ready = state.ready_todos(limit=1)
        if not ready:
            return RouterDecision(rationale="empty")
        return RouterDecision(
            assignments=[
                WorkerAssignment(
                    todo_id=ready[0].todo_id,
                    worker_name="missing-worker",
                    rationale="test unknown worker",
                )
            ],
            rationale="test unknown worker",
        )

    def summarize_round(self, state: RunState, *, results: list[WorkerResult]) -> RouterRoundSummary:
        del state
        return RouterRoundSummary(
            summary="; ".join(result.summary for result in results),
            direct_results=[result.summary for result in results],
        )


class _NoAssignmentRouter:
    def route(self, state: RunState, *, worker_catalog, max_assignments: int) -> RouterDecision:
        del state, worker_catalog, max_assignments
        return RouterDecision(rationale="intentionally empty")

    def summarize_round(self, state: RunState, *, results: list[WorkerResult]) -> RouterRoundSummary:
        del state, results
        return RouterRoundSummary(summary="empty")


class _RaisingWorker(WorkerAgent):
    name = "raising-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise LLMClientError("synthetic worker LLM failure", transient=False)


class _SuccessWorker(WorkerAgent):
    name = "success-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="ok",
        )


class _InterruptWorker(WorkerAgent):
    name = "interrupt-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise KeyboardInterrupt()


def _state() -> RunState:
    return RunState(
        objective="resilience smoke",
        authorized_scope=[],
        metadata={"challenge": {"name": "test", "category": "misc", "files": []}},
    )


class OrchestratorLoopTests(unittest.TestCase):
    def test_worker_llm_error_aborts_run(self) -> None:
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
        state = _state()
        orchestrator = Orchestrator(
            state=state,
            workers=[_RaisingWorker(), _SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )

        with self.assertRaises(LLMClientError):
            orchestrator.run(max_cycles=4)

        failing = next(todo for todo in state.todos if todo.dedupe_key == "raise-once")
        self.assertEqual(failing.status, TodoStatus.FAILED)
        self.assertEqual(state.status, RunStatus.FAILED)
        self.assertEqual(state.stop_reason, "llm_error")
        self.assertFalse(state.has_open_todos())
        self.assertFalse(any(todo.dedupe_key == "succeed-once" for todo in state.todos))
        self.assertEqual(len(state.rounds), 0)
        self.assertTrue(any("LLM error" in event for event in events))

    def test_blocked_assignment_makes_run_failed_not_completed(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[PlannedTodo(goal="Route to missing worker", dedupe_key="missing-worker")],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_UnknownWorkerRouter(),  # type: ignore[arg-type]
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)
        self.assertIn("Assignment blocked", final_state.rounds[0].summary.summary)

    def test_keyboard_interrupt_marks_running_todo_interrupted(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Interrupt once",
                        context={"worker_name": "interrupt-worker"},
                        dedupe_key="interrupt-once",
                    )
                ],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_InterruptWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.INTERRUPTED)
        self.assertEqual(final_state.todos[0].status, TodoStatus.INTERRUPTED)
        self.assertFalse(final_state.has_open_todos())

    def test_max_cycles_exhaustion_blocks_open_todos(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[PlannedTodo(goal="Leave this pending", dedupe_key="pending-on-exhaustion")],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_NoAssignmentRouter(),  # type: ignore[arg-type]
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "max_cycles_exhausted")
        self.assertFalse(final_state.has_open_todos())
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)


if __name__ == "__main__":
    unittest.main()
