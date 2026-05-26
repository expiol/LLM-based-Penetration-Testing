"""Tests for the planner-router-worker orchestrator loop."""

from __future__ import annotations
import unittest
from collections.abc import Iterable
from killchain_docker.runtime.events import EventRecorder
from killchain_docker.llm.gateway import LLMClientError, LLMFailureKind
from tests.queue_harness import todo_queue
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning.pipeline import PlanningPipeline
from killchain_docker.orchestrator.planning.schemas import (
    PlannerAgent,
    PlannedTodo,
    PlannerDecision,
)
from killchain_docker.orchestrator.round_progress_signals import (
    had_meaningful_progress,
)
from killchain_docker.orchestrator.round_result_signals import is_hollow_result
from killchain_docker.state.domain import Artifact, FlagCandidate, StateDelta
from killchain_docker.state.run_state import RunState, RunStatus
from killchain_docker.state.todos import (
    RouterDecision,
    RouterRoundSummary,
    TodoItem,
    TodoPhase,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
)
from killchain_docker.workers.worker_agent import WorkerAgent


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
        return PlannerDecision(
            summary="no more todos", todos=[], notes=[], stop_run=False
        )


class _SeedRefreshPipeline:
    def __init__(self) -> None:
        self.calls = 0

    def merge(
        self, state: RunState, *, llm_decision: PlannerDecision | None
    ) -> PlannerDecision:
        del state, llm_decision
        self.calls += 1
        return PlannerDecision(
            summary="deterministic seed refresh",
            todos=[
                PlannedTodo(
                    goal="Execute deterministic high-priority seed",
                    priority=100,
                    context={"worker_name": "success-worker"},
                    dedupe_key="seed-refresh",
                )
            ],
        )


class _PipelinePlanner(PlannerAgent):
    def __init__(self) -> None:
        self.calls = 0
        self.pipeline = _SeedRefreshPipeline()

    def plan(self, state: RunState) -> PlannerDecision:
        del state
        self.calls += 1
        return PlannerDecision(
            summary="initial backlog",
            todos=[
                PlannedTodo(
                    goal="Execute first queued todo",
                    priority=50,
                    context={"worker_name": "success-worker"},
                    dedupe_key="backlog-first",
                ),
                PlannedTodo(
                    goal="Execute second queued todo",
                    priority=10,
                    context={"worker_name": "success-worker"},
                    dedupe_key="backlog-second",
                ),
            ],
        )


class _ScriptedPlannerWithPipeline(_ScriptedPlanner):
    def __init__(self, scripts: Iterable[PlannerDecision]) -> None:
        super().__init__(scripts)
        self.pipeline = PlanningPipeline()


class _ContextRouter:
    def route(
        self, state: RunState, *, agent_directory, max_assignments: int
    ) -> RouterDecision:
        del agent_directory, max_assignments
        ready = todo_queue(state).ready(limit=1)
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

    def summarize_round(
        self, state: RunState, *, results: list[WorkerResult]
    ) -> RouterRoundSummary:
        del state
        return RouterRoundSummary(
            summary="; ".join((result.summary for result in results)),
            direct_results=[result.summary for result in results],
        )


class _UnknownWorkerRouter:
    def route(
        self, state: RunState, *, agent_directory, max_assignments: int
    ) -> RouterDecision:
        del agent_directory, max_assignments
        ready = todo_queue(state).ready(limit=1)
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

    def summarize_round(
        self, state: RunState, *, results: list[WorkerResult]
    ) -> RouterRoundSummary:
        del state
        return RouterRoundSummary(
            summary="; ".join((result.summary for result in results)),
            direct_results=[result.summary for result in results],
        )


class _NoAssignmentRouter:
    def route(
        self, state: RunState, *, agent_directory, max_assignments: int
    ) -> RouterDecision:
        del state, agent_directory, max_assignments
        return RouterDecision(rationale="intentionally empty")

    def summarize_round(
        self, state: RunState, *, results: list[WorkerResult]
    ) -> RouterRoundSummary:
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


class _AlwaysTransientWorker(WorkerAgent):
    name = "always-transient-worker"
    supported_todo_kinds = ("todo",)

    def __init__(self) -> None:
        super().__init__()
        self.calls = 0

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        self.calls += 1
        raise LLMClientError("provider connection unavailable", transient=True)


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


class _ArtifactProducerWorker(WorkerAgent):
    name = "artifact-producer"
    supported_todo_kinds = ("todo",)

    def __init__(self, artifact_path: str) -> None:
        super().__init__()
        self.artifact_path = artifact_path

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="generated artifact",
            state_delta=StateDelta(
                artifacts=[
                    Artifact(
                        path=self.artifact_path,
                        kind="png_inspect_lsb",
                        source="png_inspect",
                        digest="closure-digest",
                    )
                ]
            ),
            result_quality="artifact_generated",
        )


class _ArtifactClosureWorker(WorkerAgent):
    name = "artifact-worker"
    supported_todo_kinds = ("todo",)
    allowed_capabilities = ("artifact.triage",)
    supported_dispatch_profiles = ("artifact_analysis",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        paths = task.context.get("paths") or [task.context.get("path")]
        paths = [str(path) for path in paths if path]
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary=f"triaged {len(paths)} generated artifact(s)",
            output_context={"capability": "artifact.triage", "paths": paths},
            result_quality="artifact_triaged",
        )


class _CandidateWorker(WorkerAgent):
    name = "candidate-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="candidate recovered",
            state_delta=StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value="flag{final_cycle_ok}", source="candidate-worker"
                    )
                ]
            ),
            result_quality="candidate_recovered",
        )


class _ManyCandidateWorker(WorkerAgent):
    name = "many-candidate-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="many candidates recovered",
            state_delta=StateDelta(
                flag_candidates=[
                    FlagCandidate(value=f"flag{{candidate_{index}}}", source=self.name)
                    for index in range(5)
                ]
            ),
            result_quality="candidate_recovered",
        )


class _StreamingCandidateWorker(WorkerAgent):
    name = "streaming-candidate-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        self.report_flag_candidates(
            state, task, [FlagCandidate(value="flag{candidate_4}", source=self.name)]
        )
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="continued after candidate push",
            result_quality="candidate_recovered",
        )


class _ExpectedFlagWorker(WorkerAgent):
    name = "flag-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        candidate = str(task.context.get("candidate_flag") or "")
        if candidate in {"flag{final_cycle_ok}", "flag{candidate_4}"}:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=True,
                summary="validated",
                state_delta=StateDelta(
                    flag_candidates=[
                        FlagCandidate(
                            value=candidate, source="flag-validation", validated=True
                        )
                    ]
                ),
                solved=True,
                validated_flag=candidate,
                result_quality="flag_validated",
            )
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=False,
            summary="mismatch",
            error="candidate mismatch",
            retryable=False,
        )


class _BackgroundExpectedFlagWorker(_ExpectedFlagWorker):
    expected_flag = "flag{candidate_4}"


class _ProgressWorker(WorkerAgent):
    name = "progress-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        self.report_progress(state, task, "progress-worker choosing tool")
        self.report_progress(state, task, "progress-worker selected script.exec")
        self.report_progress(state, task, "progress-worker executing script.exec")
        self.report_progress(state, task, "progress-worker completed script.exec")
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


class _ExplodingWorker(WorkerAgent):
    name = "exploding-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise RuntimeError("synthetic worker crash")


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


class _PartialFailureWorker(WorkerAgent):
    name = "partial-failure-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=False,
            summary="script failed with useful diagnostics",
            partial=True,
            partial_reason="range too large; use bounded interpretation",
            retryable=False,
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
    def test_worker_events_include_structured_todo_context(self) -> None:
        recorder = EventRecorder(quiet=True)
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Report progress",
                            context={"worker_name": "progress-worker"},
                            dedupe_key="progress-once",
                        )
                    ],
                )
            ]
        )
        state = _state()
        orchestrator = Orchestrator(
            state=state,
            workers=[_ProgressWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=recorder.emit,
        )
        orchestrator.run(max_cycles=1)
        progress_events = [
            record
            for record in recorder.records
            if record.get("event_type") == "worker_progress"
        ]
        self.assertTrue(progress_events)
        context = progress_events[0]["context"]
        self.assertEqual(context["todo_id"], state.todos[0].todo_id)
        self.assertEqual(context["todo_status"], "running")
        self.assertEqual(context["todo_phase"], "recon")
        self.assertEqual(context["worker"], "progress-worker")
        result_events = [
            record
            for record in recorder.records
            if record.get("event_type") == "worker_result"
        ]
        self.assertTrue(result_events)
        result_context = result_events[0]["context"]
        self.assertEqual(result_context["todo_id"], state.todos[0].todo_id)
        self.assertEqual(result_context["todo_status"], "completed")
        self.assertEqual(result_context["worker"], "progress-worker")

    def test_worker_llm_error_fails_todo_and_continues(self) -> None:
        events: list[str] = []
        planner = _ScriptedPlanner(
            [
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
            ]
        )
        state = _state()
        orchestrator = Orchestrator(
            state=state,
            workers=[_RaisingWorker(), _SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )
        final_state = orchestrator.run(max_cycles=2)
        failing = next(
            (todo for todo in state.todos if todo.dedupe_key == "raise-once")
        )
        succeeding = next(
            (todo for todo in state.todos if todo.dedupe_key == "succeed-once")
        )
        self.assertEqual(failing.status, TodoStatus.FAILED)
        self.assertEqual(succeeding.status, TodoStatus.COMPLETED)
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "todo_failed")
        self.assertEqual(
            final_state.metadata["last_llm_error"]["kind"], "schema_validation"
        )
        self.assertEqual(
            final_state.metadata["last_llm_error"]["schema_name"], "ToolUseDecision"
        )
        self.assertEqual(final_state.metadata["last_llm_error"]["model"], "test-model")
        self.assertEqual(final_state.metadata["last_llm_error"]["attempts"], 2)
        self.assertFalse(todo_queue(final_state).has_open())
        self.assertEqual(len(final_state.rounds), 2)
        self.assertTrue(
            any(
                (
                    "marking" in event and "failed and continuing" in event
                    for event in events
                )
            )
        )

    def test_transient_worker_llm_error_does_not_consume_todo_attempt(self) -> None:
        events: list[str] = []
        worker = _TransientThenSuccessWorker()
        planner = _ScriptedPlanner(
            [
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
            ]
        )
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
        self.assertTrue(any(("transient LLM error" in event for event in events)))

    def test_persistent_transient_worker_llm_error_does_not_fail_todo_logic(
        self,
    ) -> None:
        events: list[str] = []
        worker = _AlwaysTransientWorker()
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Retry while provider is temporarily unavailable",
                            context={"worker_name": "always-transient-worker"},
                            dedupe_key="persistent-transient",
                        )
                    ],
                )
            ]
        )
        state = _state()
        orchestrator = Orchestrator(
            state=state,
            workers=[worker],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )
        final_state = orchestrator.run(max_cycles=Orchestrator.MAX_TRANSIENT_SKIPS + 1)
        todo = final_state.todos[0]
        self.assertEqual(worker.calls, Orchestrator.MAX_TRANSIENT_SKIPS + 1)
        self.assertEqual(todo.status, TodoStatus.INTERRUPTED)
        self.assertEqual(todo.attempts, 0)
        self.assertIn("llm_error:always-transient-worker", todo.error or "")
        self.assertFalse(
            any((item.status == TodoStatus.FAILED for item in final_state.todos))
        )
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "llm_transient_error")
        self.assertEqual(final_state.metadata["last_llm_error"]["kind"], "transient")
        self.assertTrue(final_state.metadata["last_llm_error"]["transient"])
        self.assertTrue(any(("budget exhausted" in event for event in events)))

    def test_ready_todo_backlog_executes_before_planner_refresh(self) -> None:
        events: list[str] = []
        planner = _ScriptedPlanner(
            [
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
            ]
        )
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
        self.assertTrue(any(("planner skipped" in event for event in events)))

    def test_ready_backlog_refreshes_deterministic_seeds_without_llm_planning(
        self,
    ) -> None:
        events: list[str] = []
        state = _state()
        planner = _PipelinePlanner()
        orchestrator = Orchestrator(
            state=state,
            workers=[_SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
        )
        final_state = orchestrator.run(max_cycles=3)
        by_id = {todo.todo_id: todo.dedupe_key for todo in final_state.todos}
        executed = [by_id[item.task_id] for item in final_state.execution_log]
        self.assertEqual(planner.calls, 1)
        self.assertEqual(planner.pipeline.calls, 2)
        self.assertEqual(executed, ["backlog-first", "seed-refresh", "backlog-second"])
        self.assertEqual(final_state.status, RunStatus.COMPLETED)
        self.assertTrue(
            any(("deterministic seed refresh" in event for event in events))
        )

    def test_checkpoints_long_running_activity_states(self) -> None:
        events: list[str] = []
        snapshots: list[list[str]] = []
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Checkpoint running state",
                            context={"worker_name": "progress-worker"},
                            dedupe_key="checkpoint-running",
                        )
                    ],
                )
            ]
        )

        def checkpoint(state: RunState) -> None:
            snapshots.append([str(todo.status) for todo in state.todos])

        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ProgressWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
            checkpoint_callback=checkpoint,
        )
        orchestrator.run(max_cycles=1)
        self.assertTrue(any(("planning next todos" in event for event in events)))
        self.assertTrue(any(("routing ready todos" in event for event in events)))
        self.assertTrue(any(("choosing tool" in event for event in events)))
        self.assertTrue(any(("selected" in event for event in events)))
        self.assertTrue(any(("executing" in event for event in events)))
        self.assertTrue(any(("completed" in event for event in events)))
        self.assertTrue(
            any(("summarizing worker results" in event for event in events))
        )
        self.assertIn(["running"], snapshots)
        self.assertIn(["completed"], snapshots)

    def test_checkpoint_callback_failure_logs_traceback(self) -> None:
        events: list[str] = []
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Trigger checkpoint failure",
                            context={"worker_name": "success-worker"},
                            dedupe_key="checkpoint-failure",
                        )
                    ],
                )
            ]
        )

        def checkpoint(state: RunState) -> None:
            del state
            raise RuntimeError("synthetic checkpoint failure")

        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=events.append,
            checkpoint_callback=checkpoint,
        )
        with self.assertLogs(
            "killchain_docker.orchestrator.loop", level="ERROR"
        ) as captured:
            orchestrator.run(max_cycles=1)
        self.assertTrue(
            any(
                ("checkpoint callback failed" in message for message in captured.output)
            )
        )
        self.assertTrue(any(("Traceback" in message for message in captured.output)))
        self.assertTrue(any(("failed to persist state" in event for event in events)))

    def test_unhandled_worker_exception_logs_traceback(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Crash worker once",
                            context={"worker_name": "exploding-worker"},
                            dedupe_key="worker-crash",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ExplodingWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        with self.assertLogs(
            "killchain_docker.orchestrator.loop", level="ERROR"
        ) as captured:
            final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertTrue(
            any(("worker execution failed" in message for message in captured.output))
        )
        self.assertTrue(
            any(("synthetic worker crash" in message for message in captured.output))
        )

    def test_blocked_assignment_makes_run_failed_not_completed(self) -> None:
        recorder = EventRecorder(quiet=True)
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Route to missing worker", dedupe_key="missing-worker"
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_UnknownWorkerRouter(),
            emit=recorder.emit,
        )
        final_state = orchestrator.run(max_cycles=1)
        blocked_events = [
            record
            for record in recorder.records
            if record.get("event_type") == "worker_blocked"
        ]
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "todo_blocked")
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)
        self.assertIn("Assignment blocked", final_state.rounds[0].summary.summary)
        self.assertTrue(blocked_events)
        self.assertEqual(blocked_events[0]["context"]["todo_status"], "blocked")
        self.assertEqual(blocked_events[0]["context"]["worker"], "missing-worker")

    def test_terminal_worker_failure_sets_stop_reason(self) -> None:
        planner = _ScriptedPlanner(
            [
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
            ]
        )
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
        planner = _ScriptedPlanner(
            [
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
            ]
        )
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

    def test_partial_script_failure_allows_next_planner_cycle(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Recover flag with generated solver",
                            context={"worker_name": "partial-failure-worker"},
                            dedupe_key="partial-script-failure",
                        )
                    ],
                ),
                PlannerDecision(
                    summary="cycle 2",
                    todos=[
                        PlannedTodo(
                            goal="Try corrected bounded interpretation",
                            context={"worker_name": "success-worker"},
                            dedupe_key="corrected-follow-up",
                        )
                    ],
                ),
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_PartialFailureWorker(), _SuccessWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=2)
        self.assertEqual(planner.calls, 2)
        self.assertEqual(
            {todo.dedupe_key: todo.status for todo in final_state.todos},
            {
                "partial-script-failure": TodoStatus.PARTIAL,
                "corrected-follow-up": TodoStatus.COMPLETED,
            },
        )
        self.assertEqual(final_state.stop_reason, "partial_todos_unsolved")

    def test_keyboard_interrupt_marks_running_todo_interrupted(self) -> None:
        planner = _ScriptedPlanner(
            [
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
            ]
        )
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
        self.assertFalse(todo_queue(final_state).has_open())

    def test_max_cycles_exhaustion_blocks_open_todos(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Leave this pending",
                            dedupe_key="pending-on-exhaustion",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_NoAssignmentRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "max_cycles_exhausted")
        self.assertFalse(todo_queue(final_state).has_open())
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)

    def test_final_cycle_candidate_gets_validation_pass(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Recover a candidate on the last cycle.",
                            context={"worker_name": "candidate-worker"},
                            dedupe_key="recover-last-cycle",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_CandidateWorker(), _ExpectedFlagWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(final_state.status, RunStatus.SOLVED)
        self.assertEqual(final_state.validated_flag, "flag{final_cycle_ok}")
        self.assertTrue(
            any((todo.phase == TodoPhase.FLAG_VALIDATION for todo in final_state.todos))
        )
        self.assertEqual(
            final_state.rounds[-1].planner_summary, "final flag validation pass"
        )

    def test_final_cycle_generated_artifact_gets_deterministic_closure_pass(
        self,
    ) -> None:
        artifact_path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image6_1050/lsb_all_2_msb.bin"
        planner = _ScriptedPlannerWithPipeline(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Generate a derived artifact on the last cycle.",
                            context={"worker_name": "artifact-producer"},
                            dedupe_key="generate-derived-artifact",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ArtifactProducerWorker(artifact_path), _ArtifactClosureWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        orchestrator.ROUTE_MAX_ASSIGNMENTS = 1
        final_state = orchestrator.run(max_cycles=1)
        closure_todos = [
            todo
            for todo in final_state.todos
            if isinstance(todo.context.get("dispatch_intent"), dict)
            and todo.context["dispatch_intent"].get("required_capability")
            == "artifact.triage"
        ]
        self.assertEqual(planner.calls, 1)
        self.assertEqual(len(closure_todos), 1)
        self.assertEqual(closure_todos[0].status, TodoStatus.COMPLETED)
        self.assertEqual(closure_todos[0].assigned_worker, "artifact-worker")
        self.assertEqual(closure_todos[0].context.get("path"), artifact_path)
        self.assertTrue(
            any(
                (
                    round_.planner_summary
                    == "final deterministic evidence closure pass"
                    for round_ in final_state.rounds
                )
            )
        )

    def test_generated_artifact_gets_inline_deterministic_followup_before_final_pass(
        self,
    ) -> None:
        artifact_path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/script_42/scratch/derived.bin"
        planner = _ScriptedPlannerWithPipeline(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Generate a derived artifact during the main loop.",
                            context={"worker_name": "artifact-producer"},
                            dedupe_key="generate-derived-artifact-inline",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ArtifactProducerWorker(artifact_path), _ArtifactClosureWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(planner.calls, 1)
        self.assertEqual(len(final_state.rounds), 1)
        self.assertEqual(
            [result.summary for result in final_state.rounds[0].results],
            ["generated artifact", "triaged 1 generated artifact(s)"],
        )
        self.assertFalse(
            any(
                (
                    round_.planner_summary
                    == "final deterministic evidence closure pass"
                    for round_ in final_state.rounds
                )
            )
        )

    def test_final_validation_pass_checks_all_remaining_candidates(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Recover candidates on the last cycle.",
                            context={"worker_name": "many-candidate-worker"},
                            dedupe_key="recover-many-candidates",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ManyCandidateWorker(), _ExpectedFlagWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(final_state.status, RunStatus.SOLVED)
        self.assertEqual(final_state.validated_flag, "flag{candidate_4}")

    def test_background_flag_validator_solves_without_validation_todo(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Recover candidates while validation runs in the background.",
                            context={"worker_name": "many-candidate-worker"},
                            dedupe_key="recover-many-background",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_ManyCandidateWorker(), _BackgroundExpectedFlagWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=3)
        self.assertEqual(final_state.status, RunStatus.SOLVED)
        self.assertEqual(final_state.validated_flag, "flag{candidate_4}")
        self.assertFalse(
            any((todo.phase == TodoPhase.FLAG_VALIDATION for todo in final_state.todos))
        )
        self.assertTrue(
            any(
                (
                    item.reason == "candidate mismatch"
                    for item in final_state.rejected_flag_candidates
                )
            )
        )
        self.assertNotIn(
            "flag{candidate_0}",
            {candidate.value for candidate in final_state.flag_candidates.values()},
        )

    def test_background_candidate_push_interrupts_running_worker(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Push candidate while worker is still running.",
                            context={"worker_name": "streaming-candidate-worker"},
                            dedupe_key="push-candidate-background",
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_StreamingCandidateWorker(), _BackgroundExpectedFlagWorker()],
            planner=planner,
            router=_ContextRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=3)
        self.assertEqual(final_state.status, RunStatus.SOLVED)
        self.assertEqual(final_state.validated_flag, "flag{candidate_4}")
        self.assertEqual(final_state.stop_reason, "background_flag_validated")
        self.assertEqual(final_state.todos[0].status, TodoStatus.INTERRUPTED)
        self.assertFalse(final_state.rounds)

    def test_no_todos_created_is_terminal_failure(self) -> None:
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=_ScriptedPlanner([]),
            router=_NoAssignmentRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=1)
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "no_todos_created")
        self.assertEqual(final_state.todos, [])

    def test_empty_router_rounds_have_terminal_stop_reason(self) -> None:
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(goal="Never assigned", dedupe_key="router-empty")
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_NoAssignmentRouter(),
            emit=lambda _: None,
        )
        final_state = orchestrator.run(max_cycles=4)
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "router_no_assignments")
        self.assertFalse(todo_queue(final_state).has_open())
        self.assertEqual(final_state.todos[0].status, TodoStatus.BLOCKED)

    def test_planner_missing_dependency_is_dropped_before_dispatch(
        self,
    ) -> None:
        recorder = EventRecorder(quiet=True)
        planner = _ScriptedPlanner(
            [
                PlannerDecision(
                    summary="cycle 1",
                    todos=[
                        PlannedTodo(
                            goal="Use an upstream result that is not in the queue.",
                            dedupe_key="dependency-missing",
                            depends_on=["missing-upstream"],
                        )
                    ],
                )
            ]
        )
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_SuccessWorker()],
            planner=planner,
            router=_NoAssignmentRouter(),
            emit=recorder.emit,
        )
        final_state = orchestrator.run(max_cycles=2)
        dependency_events = [
            record
            for record in recorder.records
            if record.get("event_type") == "todo_dependency_blocked"
        ]
        self.assertEqual(final_state.status, RunStatus.FAILED)
        self.assertEqual(final_state.stop_reason, "no_todos_created")
        self.assertEqual(final_state.todos, [])
        self.assertTrue(
            any(
                ("dependency gate dropped" in note)
                for note in final_state.orchestration_notes
            )
        )
        self.assertEqual(orchestrator.dispatch_rounds.consecutive_empty_rounds, 2)
        self.assertFalse(dependency_events)


class HollowResultAndProgressTests(unittest.TestCase):
    def test_hollow_result_marked_partial(self) -> None:
        """A worker that reports success=True but produces no state signals
        should be downgraded to partial by the orchestrator."""
        from killchain_docker.state.domain import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=True,
            summary="curl GET http://example.com/: HTTP 200",
            state_delta=StateDelta(),
        )
        self.assertTrue(is_hollow_result(result))

    def test_non_hollow_result_with_findings(self) -> None:
        """A successful result that carries finding_updates is NOT hollow."""
        from killchain_docker.state.domain import Finding, Severity, StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=True,
            summary="found SQL injection",
            state_delta=StateDelta(),
            finding_updates=[
                Finding(finding_id="f-1", title="SQLi", severity=Severity.HIGH)
            ],
        )
        self.assertFalse(is_hollow_result(result))

    def test_non_hollow_result_with_stdout_observation(self) -> None:
        """Raw stdout is evidence the planner can use, even without typed deltas."""
        from killchain_docker.state.domain import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="artifact-worker",
            success=True,
            summary="shell: xxd -l 64 flag.stfu",
            output_context={"stdout": "00000000: 5354 4655 6aab 0223"},
            state_delta=StateDelta(),
        )
        self.assertFalse(is_hollow_result(result))

    def test_non_hollow_result_with_evidence_observation(self) -> None:
        """Evidence stdout also prevents a successful result being called hollow."""
        from killchain_docker.state.domain import EvidenceRecord, StateDelta

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
        self.assertFalse(is_hollow_result(result))

    def test_non_hollow_result_with_flag_candidates(self) -> None:
        """A successful result with flag_candidates in state_delta is NOT hollow."""
        from killchain_docker.state.domain import FlagCandidate, StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="exploit-worker",
            success=True,
            summary="flag found",
            state_delta=StateDelta(
                flag_candidates=[FlagCandidate(value="flag{ok}", source="test")]
            ),
        )
        self.assertFalse(is_hollow_result(result))

    def test_failed_result_is_never_hollow(self) -> None:
        """A failed result should not be treated as hollow."""
        from killchain_docker.state.domain import StateDelta

        result = WorkerResult(
            todo_id="todo-1",
            worker_name="web-worker",
            success=False,
            summary="connection refused",
            state_delta=StateDelta(),
        )
        self.assertFalse(is_hollow_result(result))

    def test_progress_includes_non_flag_state_delta(self) -> None:
        """Findings and credentials count as meaningful progress,
        preventing a premature forced pivot."""
        from killchain_docker.state.domain import Finding, Severity, StateDelta

        results = [
            WorkerResult(
                todo_id="todo-1",
                worker_name="web-worker",
                success=True,
                summary="discovered vulnerability",
                state_delta=StateDelta(),
                finding_updates=[
                    Finding(finding_id="f-1", title="XSS", severity=Severity.MEDIUM)
                ],
            )
        ]
        self.assertTrue(had_meaningful_progress(results))

    def test_no_progress_when_all_results_empty(self) -> None:
        """A round where all results are hollow has no progress."""
        from killchain_docker.state.domain import StateDelta

        results = [
            WorkerResult(
                todo_id="todo-1",
                worker_name="web-worker",
                success=True,
                summary="curl GET: HTTP 200",
                state_delta=StateDelta(),
            )
        ]
        self.assertFalse(had_meaningful_progress(results))


if __name__ == "__main__":
    unittest.main()
