"""Tests for the planner-router-worker orchestrator loop."""

from __future__ import annotations

import unittest
from collections.abc import Iterable

from killchain_docker.llm import LLMClientError, LLMFailureKind
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning import PlannerAgent, PlannedTodo, PlannerDecision
from killchain_docker.orchestrator.policy import RoundOutcomePolicy
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
        self.calls = 0

    def plan(self, state: RunState) -> PlannerDecision:
        del state
        self.calls += 1
        if self._cursor < len(self._scripts):
            decision = self._scripts[self._cursor]
            self._cursor += 1
            return decision
        return PlannerDecision(summary="no more todos", todos=[], notes=[], stop_run=False)


class _ContextRouter:
    def route(self, state: RunState, *, worker_directory, max_assignments: int) -> RouterDecision:
        del worker_directory, max_assignments
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
    def route(self, state: RunState, *, worker_directory, max_assignments: int) -> RouterDecision:
        del worker_directory, max_assignments
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
    def route(self, state: RunState, *, worker_directory, max_assignments: int) -> RouterDecision:
        del state, worker_directory, max_assignments
        return RouterDecision(rationale="intentionally empty")

    def summarize_round(self, state: RunState, *, results: list[WorkerResult]) -> RouterRoundSummary:
        del state, results
        return RouterRoundSummary(summary="empty")


class _RaisingWorker(WorkerAgent):
    name = "raising-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise LLMClientError(
            "synthetic worker LLM failure",
            kind=LLMFailureKind.SCHEMA_VALIDATION,
            schema_name="ToolUseDecision",
            model="test-model",
            attempts=2,
        )


class _TransientThenSuccessWorker(WorkerAgent):
    name = "transient-worker"
    supported_todo_kinds = ("todo",)

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        self.calls += 1
        if self.calls == 1:
            raise LLMClientError("connection dropped", transient=True)
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="ok after transient",
            result_quality="transient_recovered",
        )


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
            result_quality="test_success",
        )


class _FailedWorker(WorkerAgent):
    name = "failed-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=False,
            summary="tool failed",
            error="synthetic terminal failure",
            retryable=False,
        )


class _PartialWorker(WorkerAgent):
    name = "partial-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="script produced no flag",
            partial=True,
            partial_reason="script completed with no flag candidate",
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
        self.assertEqual(state.metadata["last_llm_error"]["kind"], "schema_validation")
        self.assertEqual(state.metadata["last_llm_error"]["schema_name"], "ToolUseDecision")
        self.assertEqual(state.metadata["last_llm_error"]["model"], "test-model")
        self.assertEqual(state.metadata["last_llm_error"]["attempts"], 2)
        self.assertFalse(state.has_open_todos())
        self.assertFalse(any(todo.dedupe_key == "succeed-once" for todo in state.todos))
        self.assertEqual(len(state.rounds), 0)
        self.assertTrue(any("LLM error" in event for event in events))

    def test_transient_worker_llm_error_does_not_consume_todo_attempt(self) -> None:
        events: list[str] = []
        worker = _TransientThenSuccessWorker()
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Retry after infrastructure hiccup",
                        context={"worker_name": "transient-worker"},
                        dedupe_key="transient-once",
                    )
                ],
            )
        ])
        state = _state()
        orchestrator = Orchestrator(
            state=state,
            workers=[worker],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )

        final_state = orchestrator.run(max_cycles=2)

        todo = final_state.todos[0]
        self.assertEqual(planner.calls, 1)
        self.assertEqual(worker.calls, 2)
        self.assertEqual(todo.status, TodoStatus.COMPLETED)
        self.assertEqual(todo.attempts, 1)
        self.assertIsNone(todo.error)
        self.assertEqual(final_state.status, RunStatus.COMPLETED)
        self.assertEqual(final_state.stop_reason, "unsolved_no_work_remaining")
        self.assertTrue(any("transient LLM error" in event for event in events))

    def test_ready_todo_backlog_executes_before_planner_refresh(self) -> None:
        events: list[str] = []
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Execute first queued todo",
                        context={"worker_name": "success-worker"},
                        dedupe_key="backlog-first",
                    ),
                    PlannedTodo(
                        goal="Execute second queued todo",
                        context={"worker_name": "success-worker"},
                        dedupe_key="backlog-second",
                    ),
                ],
            ),
            PlannerDecision(
                summary="should not run while backlog exists",
                todos=[
                    PlannedTodo(
                        goal="Planner refreshed before backlog drained",
                        priority=100,
                        context={"worker_name": "success-worker"},
                        dedupe_key="planner-called-too-early",
                    )
                ],
            ),
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )

        final_state = orchestrator.run(max_cycles=2)

        self.assertEqual(planner.calls, 1)
        self.assertEqual(final_state.status, RunStatus.COMPLETED)
        self.assertEqual(final_state.stop_reason, "unsolved_no_work_remaining")
        self.assertEqual(
            {todo.dedupe_key: todo.status for todo in final_state.todos},
            {
                "backlog-first": TodoStatus.COMPLETED,
                "backlog-second": TodoStatus.COMPLETED,
            },
        )
        self.assertTrue(any("planner skipped" in event for event in events))

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
        self.assertEqual(final_state.stop_reason, "todo_blocked")
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)
        self.assertIn("Assignment blocked", final_state.rounds[0].summary.summary)

    def test_terminal_worker_failure_sets_stop_reason(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Fail once",
                        context={"worker_name": "failed-worker"},
                        dedupe_key="terminal-failure",
                    )
                ],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_FailedWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "todo_failed")
        self.assertEqual(final_state.todos[0].status, TodoStatus.FAILED)

    def test_terminal_partial_todo_sets_stop_reason(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[
                    PlannedTodo(
                        goal="Recover flag",
                        context={"worker_name": "partial-worker"},
                        dedupe_key="partial-no-flag",
                    )
                ],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_PartialWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "partial_todos_unsolved")
        self.assertEqual(final_state.todos[0].status, TodoStatus.PARTIAL)

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
        self.assertEqual(final_state.stop_reason, "interrupted")
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

    def test_no_todos_created_is_terminal_failure(self) -> None:
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=_ScriptedPlanner([]),
            router=_NoAssignmentRouter(),  # type: ignore[arg-type]
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=1)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "no_todos_created")
        self.assertEqual(final_state.todos, [])

    def test_empty_router_rounds_have_terminal_stop_reason(self) -> None:
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                todos=[PlannedTodo(goal="Never assigned", dedupe_key="router-empty")],
            )
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_NoAssignmentRouter(),  # type: ignore[arg-type]
            emit=lambda _: None,
        )

        final_state = orchestrator.run(max_cycles=4)

        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "router_no_assignments")
        self.assertFalse(final_state.has_open_todos())
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)


class HollowResultAndProgressTests(unittest.TestCase):
    def test_hollow_result_marked_partial(self) -> None:
        """A worker that reports success=True but produces no state signals
        should be downgraded to partial by the orchestrator."""
        from killchain_docker.state import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=True,
            summary="curl GET http://example.com/: HTTP 200",
            state_delta=StateDelta(),
        )

        self.assertTrue(RoundOutcomePolicy.is_hollow_result(result))

    def test_non_hollow_result_with_findings(self) -> None:
        """A successful result that carries finding_updates is NOT hollow."""
        from killchain_docker.state import Finding, Severity, StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=True,
            summary="found SQL injection",
            state_delta=StateDelta(),
            finding_updates=[
                Finding(finding_id="f-1", title="SQLi", severity=Severity.HIGH),
            ],
        )

        self.assertFalse(RoundOutcomePolicy.is_hollow_result(result))

    def test_non_hollow_result_with_stdout_observation(self) -> None:
        """Raw stdout is evidence the planner can use, even without typed deltas."""
        from killchain_docker.state import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="artifact-worker",
            success=True,
            summary="shell: xxd -l 64 flag.stfu",
            output_context={"stdout": "00000000: 5354 4655 6aab 0223"},
            state_delta=StateDelta(),
        )

        self.assertFalse(RoundOutcomePolicy.is_hollow_result(result))

    def test_non_hollow_result_with_evidence_observation(self) -> None:
        """Evidence stdout also prevents a successful result being called hollow."""
        from killchain_docker.state import EvidenceRecord, StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="artifact-worker",
            success=True,
            summary="shell: xxd -l 64 flag.stfu",
            state_delta=StateDelta(),
            evidence_updates=[
                EvidenceRecord(
                    task_id="todo-1",
                    capability="shell.exec",
                    tool_name="shell_exec",
                    mode="local_command",
                    summary="shell",
                    extracted={"output_context": {"stdout": "hexdump output"}},
                )
            ],
        )

        self.assertFalse(RoundOutcomePolicy.is_hollow_result(result))

    def test_non_hollow_result_with_flag_candidates(self) -> None:
        """A successful result with flag_candidates in state_delta is NOT hollow."""
        from killchain_docker.state import FlagCandidate, StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="exploit-worker",
            success=True,
            summary="flag found",
            state_delta=StateDelta(
                flag_candidates=[FlagCandidate(value="flag{ok}", source="test")],
            ),
        )

        self.assertFalse(RoundOutcomePolicy.is_hollow_result(result))

    def test_failed_result_is_never_hollow(self) -> None:
        """A failed result should not be treated as hollow."""
        from killchain_docker.state import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=False,
            summary="connection refused",
            state_delta=StateDelta(),
        )

        self.assertFalse(RoundOutcomePolicy.is_hollow_result(result))

    def test_progress_includes_non_flag_state_delta(self) -> None:
        """Findings and credentials count as meaningful progress,
        preventing a premature forced pivot."""
        from killchain_docker.state import Finding, Severity, StateDelta

        results = [
            WorkerResult(
                todo_id="todo-1",
                worker_name="web-worker",
                success=True,
                summary="discovered vulnerability",
                state_delta=StateDelta(),
                finding_updates=[
                    Finding(finding_id="f-1", title="XSS", severity=Severity.MEDIUM),
                ],
            ),
        ]

        self.assertTrue(RoundOutcomePolicy.had_meaningful_progress(results))

    def test_no_progress_when_all_results_empty(self) -> None:
        """A round where all results are hollow has no progress."""
        from killchain_docker.state import StateDelta

        results = [
            WorkerResult(
                todo_id="todo-1",
                worker_name="web-worker",
                success=True,
                summary="curl GET: HTTP 200",
                state_delta=StateDelta(),
            ),
        ]

        self.assertFalse(RoundOutcomePolicy.had_meaningful_progress(results))


if __name__ == "__main__":
    unittest.main()
