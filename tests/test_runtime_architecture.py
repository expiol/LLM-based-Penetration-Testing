"""Architecture-level tests for the refactored runtime seams."""

from __future__ import annotations
import inspect
import importlib.util
from pathlib import Path
import ast
from typing import get_type_hints
import unittest
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from killchain_docker.orchestrator.agent_lifecycle import (
    AgentLifecycle,
    AgentRuntimeState,
    AgentStatus,
)
from killchain_docker.orchestrator.dispatch.controller import DispatchCycleController
from killchain_docker.orchestrator.dispatch.types import (
    DependencyState,
    DispatchCycleResult,
    EmptyDispatchAction,
    select_ready_batch,
)
from killchain_docker.orchestrator.background_flags import (
    BackgroundFlagValidationController,
)
from killchain_docker.orchestrator.dispatch.planner import AssignmentPlanner
from killchain_docker.orchestrator.closure.policy import DeterministicClosurePolicy
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.orchestrator.planning.cycle_controller import (
    PlanningCycleController,
)
from killchain_docker.orchestrator.planning.queue_refresh import (
    PlanningRefreshController,
)
from killchain_docker.orchestrator.planning.schemas import PlannedTodo, PlannerDecision
from killchain_docker.orchestrator.execution import (
    BatchExecutionOutcome,
    Execution,
    routed_transient_llm_handling,
)
from killchain_docker.orchestrator.closure.controller import ClosureExecutionController
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.progress.run_progress import RunProgressController
from killchain_docker.orchestrator.run_termination import (
    LLMFailureAction,
    RunTerminationController,
)
from killchain_docker.orchestrator.runtime_tasks import (
    AssignmentLifecycleController,
    RuntimeTaskRegistry,
    RuntimeTaskState,
    RuntimeTaskStatus,
    is_terminal_runtime_task_status,
)
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.state.artifact_store import ArtifactFactStore
from killchain_docker.state.candidate_facts import FlagCandidateStore
from killchain_docker.state.evidence_facts import EvidenceFactStore
from killchain_docker.state.execution_facts import ExecutionFactStore
from killchain_docker.state.recon_facts import ReconFactStore
from killchain_docker.state.journal import RunJournal
from killchain_docker.memory.policy import MemoryWritePolicy
from killchain_docker.memory.store import RunMemoryStore
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.domain import (
    Endpoint,
    ExploitAttempt,
    FlagCandidate,
    Artifact,
    EvidenceRecord,
    Hypothesis,
    NetworkEdge,
    Route,
    Session,
    Vulnerability,
)
from killchain_docker.state.run_state import RunState, RunStatus
from killchain_docker.state.todos import (
    RouterDecision,
    RouterRoundSummary,
    TodoItem,
    TodoPhase,
    TodoStatus,
    WorkerAssignment,
    WorkerResult,
    normalize_todo_phase,
)
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.memory.projection import RunMemoryProjection
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.state_delta import StateDeltaApplier
from killchain_docker.state.worker_results import WorkerResultApplier
from killchain_docker.workers.corrections.counters import bounded_counter_candidates
from killchain_docker.tools.capabilities import (
    ToolCapability,
    dispatch_profile_spec,
    normalize_dispatch_profile,
    tool_spec,
    worker_preferences_for_profile,
)
from killchain_docker.tools.core import ToolInterruptBehavior
from killchain_docker.workers.runtime.agent import WorkerAgent

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKERS_ROOT = PROJECT_ROOT / "killchain_docker/workers"


def worker_source(relative: str) -> str:
    return (WORKERS_ROOT / relative).read_text()


def _has_state_attr_access(source: str, *attrs: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in attrs
            and isinstance(node.value, ast.Name)
            and node.value.id == "state"
        ):
            return True
    return False


def _has_self_state_attr_access(source: str, *attrs: str) -> bool:
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Attribute) and node.attr in attrs):
            continue
        value = node.value
        if (
            isinstance(value, ast.Attribute)
            and value.attr == "state"
            and isinstance(value.value, ast.Name)
            and value.value.id == "self"
        ):
            return True
    return False


def _has_run_state_attr_access(source: str, *attrs: str) -> bool:
    return _has_state_attr_access(source, *attrs) or _has_self_state_attr_access(
        source, *attrs
    )


def _todo_queue(state: RunState) -> TodoQueue:
    return TodoQueue(state)


class _RuntimeWorker(WorkerAgent):
    supported_todo_kinds = ("todo",)
    routing_summary = "runtime worker"
    preferred_challenge_categories = ()
    required_context_keys = ()
    supported_dispatch_profiles = ("open",)
    allowed_capabilities = ()

    def __init__(self, name: str = "runtime-worker", *, fail: bool = False) -> None:
        super().__init__()
        self.name = name
        self.fail = fail

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        if self.fail:
            raise RuntimeError("boom")
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="done",
            memory_updates={"format": "png"},
        )


class _ExpectedFlagWorker(WorkerAgent):
    name = "flag-worker"
    supported_todo_kinds = ("todo",)
    expected_flag = "flag{ok}"

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del task, state
        raise AssertionError("background validator should not execute flag worker")


class _RefreshPlanner:
    def __init__(self, decision: PlannerDecision) -> None:
        self.decision = decision
        self.calls = 0

    def plan(self, state: RunState) -> PlannerDecision:
        del state
        self.calls += 1
        return self.decision


class _TransientBacklogSeedPipeline:
    def __init__(self) -> None:
        self.calls = 0

    def merge(self, state: RunState, *, llm_decision: PlannerDecision):
        del state, llm_decision
        self.calls += 1
        return PlannerDecision(
            summary="deterministic seed refresh",
            todos=[
                PlannedTodo(
                    goal="Seed todo should not be created after transient skip.",
                    dedupe_key="seed-after-transient",
                )
            ],
        )


class _SummaryRouter:
    def __init__(self) -> None:
        self.calls = 0
        self.assignments: list[WorkerAssignment] = []

    def route(
        self, state: RunState, *, agent_directory, max_assignments: int
    ) -> RouterDecision:
        del state, agent_directory, max_assignments
        return RouterDecision(assignments=list(self.assignments))

    def summarize_round(self, state: RunState, *, results: list[WorkerResult]):
        del state
        self.calls += 1
        return RouterRoundSummary(
            summary="; ".join((result.summary for result in results)),
            direct_results=[result.summary for result in results],
        )


class _DispatchRouter:
    def __init__(self, decision: RouterDecision) -> None:
        self.decision = decision
        self.calls = 0

    def route(
        self, state: RunState, *, agent_directory, max_assignments: int
    ) -> RouterDecision:
        del state, agent_directory
        self.calls += 1
        self.max_assignments = max_assignments
        return self.decision


class _DispatchExecution:
    def __init__(self) -> None:
        self.calls = 0

        class _Outcome:
            is_solved = False

        self.outcome = _Outcome()

    def run_assignments(
        self, *, cycle, todos, select_worker, rationale, event_label,
        transient_llm, concurrent, budget=None,
    ) -> BatchExecutionOutcome:
        del select_worker, rationale, event_label, transient_llm, concurrent, budget
        self.calls += 1
        return BatchExecutionOutcome(
            results=[
                WorkerResult(
                    todo_id=todos[0].todo_id,
                    worker_name="runtime-worker",
                    success=True,
                    summary=f"cycle {cycle} executed",
                )
            ],
            executed_assignments=[
                WorkerAssignment(
                    todo_id=todos[0].todo_id, worker_name="runtime-worker"
                )
            ],
        )


class _StubClosure:
    """Inline-followup is a no-op for these tests."""

    def __init__(self) -> None:
        self.calls = 0

    def inline_deterministic_followup(
        self, *, cycle, remaining_budget, planner, max_assignments
    ):
        del cycle, remaining_budget, planner, max_assignments
        self.calls += 1
        return ([], [])


class _NoopTermination:
    def handle_step_llm_error(self, **kwargs):
        del kwargs
        raise AssertionError("unexpected LLM error")

    def note_successful_step(self, source: str | None = None) -> None:
        del source
        return None


class _BackgroundLifecycleFlags:
    def __init__(self) -> None:
        self.started = 0
        self.stopped = 0

    def start(self) -> None:
        self.started += 1

    def stop(self) -> None:
        self.stopped += 1



class RuntimeArchitectureTests(unittest.TestCase):
    def _runtime_events(
        self,
        state: RunState,
        events: list[tuple[str, dict[str, object]]] | None = None,
        checkpoints: list[bool] | None = None,
    ) -> RuntimeEventController:
        event_records = events if events is not None else []
        checkpoint_records = checkpoints if checkpoints is not None else []

        def emit(
            message: str, *, event_type: str | None = None, **kwargs: object
        ) -> None:
            if event_type is not None:
                kwargs["event_type"] = event_type
            event_records.append((message, kwargs))

        return RuntimeEventController(
            state=state, emit=emit, checkpoint=lambda: checkpoint_records.append(True)
        )

    def test_run_memory_store_bounds_and_projects_index(self) -> None:
        raw: dict[str, str] = {}
        store = RunMemoryStore(raw, limit=2)
        entries = store.upsert_many({"a": "1", "b": 2, "c": "3"})
        self.assertEqual(raw, {"b": "2", "c": "3"})
        self.assertEqual([entry.key for entry in entries], ["a", "b", "c"])
        snapshot = store.index_snapshot(title="Test Memory")
        self.assertIn("# Test Memory", snapshot.index_markdown)
        self.assertIn("[c](memory://c) - 3", snapshot.index_markdown)
        self.assertEqual(snapshot.entrypoint_name, "MEMORY.md")
        self.assertEqual(store.prompt_entries(), {"b": "2", "c": "3"})

    def test_run_memory_store_owns_numeric_hint_projection(self) -> None:
        raw = {
            "expected_length": "try length=0x20 first",
            "notes": "declared size: 512 bytes",
            "noise": "hello",
        }
        store = RunMemoryStore(raw)
        hints = store.numeric_hints(limit=1024)
        self.assertIn(
            {"label": "expected_length", "value": 32, "source": "run_memory"}, hints
        )
        self.assertIn(
            {"label": "declared_size", "value": 512, "source": "run_memory"}, hints
        )

    def test_specific_projections_own_runtime_views(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Inspect service."))
        queue.start(todo, "analysis-worker")
        report_projection = RunReportProjection(state)
        summary = report_projection.summary()
        self.assertEqual(summary["todos"], 1)
        self.assertEqual(summary["open_todos"], 1)
        self.assertEqual(
            report_projection.metrics()["todo_status_counts"], {"running": 1}
        )
        self.assertEqual(
            report_projection.metrics()["worker_counts"], {"analysis-worker": 1}
        )
        self.assertEqual(report_projection.current_status_todo(), todo)
        self.assertEqual(
            report_projection.open_or_recent_todos()[0]["todo_id"], todo.todo_id
        )
        self.assertEqual(report_projection.compact_rounds(), [])
        self.assertEqual(report_projection.compact_flag_candidates(), [])
        self.assertEqual(report_projection.compact_hypotheses_tail(), [])
        self.assertEqual(report_projection.compact_orchestration_notes_tail(), [])
        self.assertEqual(EvidenceProjectionStore(state).payload(), {"evidence": {}})
        self.assertEqual(report_projection.router_round_summaries(), [])
        self.assertEqual(RunMemoryProjection(state).prompt_entries(), {})
        self.assertEqual(RunMemoryProjection(state).numeric_hints(), [])
        self.assertFalse(hasattr(RunState, "summary"))
        self.assertFalse(hasattr(RunState, "working_memory"))

    def test_runtime_reporting_uses_report_projection_views(self) -> None:
        source = "\n".join(
            [
                (PROJECT_ROOT / "killchain_docker/runtime/compact_log.py").read_text(),
                (PROJECT_ROOT / "killchain_docker/runtime/persistence.py").read_text(),
            ]
        )
        self.assertNotIn("RunStateProjection", source)
        self.assertIn("ChallengeProjection", source)
        self.assertIn("RunMemoryProjection", source)
        self.assertIn("EvidenceProjectionStore", source)
        self.assertIn("RunReportProjection", source)
        self.assertIn(".metrics()", source)
        self.assertIn(".current_status_todo()", source)
        self.assertIn(".open_or_recent_todos()", source)
        self.assertIn(".compact_rounds()", source)
        self.assertIn(".compact_flag_candidates()", source)
        self.assertIn(".compact_hypotheses_tail()", source)
        self.assertIn(".compact_orchestration_notes_tail()", source)
        self.assertIn(".payload()", source)
        self.assertIn(".prompt_entries(", source)
        self.assertFalse(_has_state_attr_access(source, "todos", "rounds"))
        self.assertNotIn("state.orchestration_notes", source)
        self.assertNotIn("state.flag_candidates.values", source)
        self.assertNotIn("state.hypotheses.values", source)
        self.assertNotIn("state.evidence.items", source)
        self.assertNotIn("state.run_memory", source)
        self.assertNotIn("_todo_status_counts", source)
        self.assertNotIn("_worker_counts", source)
        self.assertNotIn("_current_status_todo", source)
        self.assertNotIn("_compact_todos", source)
        self.assertNotIn("_compact_rounds", source)

    def test_markdown_reporting_uses_projection_payload(self) -> None:
        source = (PROJECT_ROOT / "killchain_docker/reporting.py").read_text()
        self.assertIn("RunReportProjection", source)
        self.assertIn(".markdown_report_payload()", source)
        self.assertFalse(
            _has_state_attr_access(
                source,
                "todos",
                "rounds",
                "assets",
                "findings",
                "evidence",
                "metadata",
            )
        )

    def test_planner_context_uses_projection_for_state_snapshots(self) -> None:
        source_paths = [
            "killchain_docker/orchestrator/planning/context_builder.py",
            "killchain_docker/orchestrator/planning/context_temperature.py",
            "killchain_docker/orchestrator/planning/stagnation_context.py",
        ]
        source = "\n".join((PROJECT_ROOT / path).read_text() for path in source_paths)
        self.assertIn("PlannerStateProjection", source)
        self.assertIn(".assets(", source)
        self.assertIn(".execution_log(", source)
        self.assertIn("RunReportProjection", source)
        forbidden = (
            "state.assets.",
            "state.endpoints.",
            "state.findings.",
            "state.evidence.",
            "state.rounds.",
            "state.execution_log.",
            "state.flag_candidates.",
            "state.run_memory.",
        )
        for pattern in forbidden:
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, source)

    def test_planning_seed_details_are_split_by_strategy(self) -> None:
        seed_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/planning/seed_planner.py"
        ).read_text()
        artifact_followup_source = (
            PROJECT_ROOT
            / "killchain_docker/orchestrator/planning/artifact_followup_seeds.py"
        ).read_text()
        suspicious_media_source = (
            PROJECT_ROOT
            / "killchain_docker/orchestrator/planning/suspicious_media_seeds.py"
        ).read_text()
        disk_extract_source = (
            PROJECT_ROOT
            / "killchain_docker/orchestrator/planning/disk_extract_seeds.py"
        ).read_text()
        recovery_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/planning/recovery_seeds.py"
        ).read_text()
        near_miss_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/planning/near_miss_seeds.py"
        ).read_text()
        self.assertFalse(
            (
                PROJECT_ROOT
                / "killchain_docker/orchestrator/planning/artifact_seeds.py"
            ).exists()
        )
        self.assertIn("ArtifactFollowupSeedPlanner", seed_source)
        self.assertIn("SuspiciousMediaSeedPlanner", seed_source)
        self.assertIn("DiskExtractSeedPlanner", seed_source)
        self.assertIn("RecoverySeedPlanner", seed_source)
        self.assertIn("NearMissSeedPlanner", seed_source)
        for forbidden in (
            "sorted_artifact_followups",
            "disk_image_artifacts",
            "media_scan_evidence_records",
            "rejected_flag_candidate_records",
            "near_miss_evidence_records",
            "sorted_followups",
            "disk_images",
            "media_scan_records",
            "rejected_records",
            "near_miss_records",
            "_STRONG_TERMS",
            "_PROTOCOL_TERMS",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, seed_source)
        self.assertIn("sorted_followups", artifact_followup_source)
        self.assertIn("media_scan_records", suspicious_media_source)
        self.assertIn("disk_images", disk_extract_source)
        self.assertIn("near_miss_records", near_miss_source)

    def test_policy_modules_use_metadata_store_or_projection(self) -> None:
        todo_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/normalization.py"
        ).read_text()
        candidate_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/candidate_policy.py"
        ).read_text()
        progress_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/progress/gate.py"
        ).read_text()
        rag_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/rag_policy.py"
        ).read_text()
        self.assertIn("ChallengeProjection", todo_source)
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.todo_artifacts")
        )
        artifact_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/artifact_targets.py"
        ).read_text()
        reference_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/artifact_references.py"
        ).read_text()
        self.assertIn("ArtifactProjectionStore", artifact_source)
        self.assertIn("ArtifactProjectionStore", reference_source)
        self.assertIn("ChallengeProjection", candidate_source)
        self.assertIn("RunMetadataStore", progress_source)
        self.assertIn("RunMetadataStore", rag_source)
        direct_sources = "\n".join(
            [
                todo_source,
                artifact_source,
                reference_source,
                candidate_source,
                progress_source,
                rag_source,
            ]
        )
        direct_sources = direct_sources.replace("killchain_docker.state.metadata", "")
        self.assertNotIn("state.metadata", direct_sources)

    def test_todo_artifact_normalizers_own_artifact_path_and_target_logic(self) -> None:
        todo_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/normalization.py"
        ).read_text()
        reference_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/artifact_references.py"
        ).read_text()
        target_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/todo/artifact_targets.py"
        ).read_text()
        capability_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/artifact_capability.py"
        ).read_text()
        self.assertIn("DurableArtifactReferenceNormalizer", todo_source)
        self.assertIn("TodoArtifactTargetNormalizer", todo_source)
        for forbidden in (
            "_rewrite_files_root_artifact_paths",
            "_referenced_artifact_directory_prefixes",
            "_durable_paths_from_relative_context",
            "artifact_projection_by_relative_path",
            "unique_artifact_mentioned",
            "disk_image_artifacts",
            "by_relative_path",
            "unique_mentioned",
            "disk_images",
            "requested_capability_targets_artifact",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, todo_source)
        self.assertIn("_rewrite_files_root_artifact_paths", reference_source)
        self.assertIn("by_relative_path", reference_source)
        self.assertIn("unique_mentioned", target_source)
        self.assertIn("requested_capability_targets_artifact", capability_source)
        self.assertIn("disk_images", target_source)

    def test_state_projection_split_into_consumer_specific_views(self) -> None:
        report_source = (
            PROJECT_ROOT / "killchain_docker/state/report_projection.py"
        ).read_text()
        artifact_source = (
            PROJECT_ROOT / "killchain_docker/state/artifact_projection.py"
        ).read_text()
        planner_source = (
            PROJECT_ROOT / "killchain_docker/state/planner_projection.py"
        ).read_text()
        self.assertIsNone(importlib.util.find_spec("killchain_docker.state.projection"))
        for forbidden in (
            "def _relative_path",
            "facts_from_artifact",
            "artifact_followup_priority",
            "def planner_assets",
            "def planner_continuation",
            "PlannerStateProjection",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, report_source)
        self.assertIn("def markdown_report_payload", report_source)
        self.assertIn("def runtime_error_line", report_source)
        self.assertIn("facts_from_artifact", artifact_source)
        self.assertIn("artifact_followup_priority", artifact_source)
        self.assertIn("def assets", planner_source)
        self.assertIn("def continuation", planner_source)

    def test_planning_pipeline_uses_projection_for_scope_and_grounding_facts(
        self,
    ) -> None:
        source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/planning/pipeline.py"
        ).read_text()
        self.assertIn("ChallengeProjection", source)
        self.assertIn(".files()", source)
        self.assertIn(".paths()", source)
        self.assertIn(".exploit_grounded(", source)
        self.assertNotIn("_refs_observed_endpoint", source)
        self.assertNotIn("_endpoint_has_positive_observation", source)
        self.assertNotIn("ContextRefPolicy", source)
        for pattern in (
            "state.vulnerabilities",
            "state.credentials",
            "state.sessions",
            "state.findings",
            "state.hypotheses",
            "state.endpoints",
        ):
            with self.subTest(pattern=pattern):
                self.assertNotIn(pattern, source)

    def test_core_artifact_reads_go_through_projection(self) -> None:
        source_paths = [
            "killchain_docker/orchestrator/planning/pipeline.py",
            "killchain_docker/orchestrator/todo/normalization.py",
            "killchain_docker/orchestrator/closure/policy.py",
        ]
        for source_path in source_paths:
            with self.subTest(source_path=source_path):
                source = (PROJECT_ROOT / source_path).read_text()
                self.assertNotIn("RunStateProjection", source)
                self.assertNotIn("state.artifacts", source)
                self.assertNotIn("facts_from_artifact", source)
                self.assertNotIn("artifact_followup_priority", source)
                self.assertNotIn("artifact_followup_capability", source)

    def test_llm_planner_uses_projection_for_continuation_facts(self) -> None:
        source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/planning/planner.py"
        ).read_text()
        self.assertIn("PlannerStateProjection", source)
        self.assertIn(".continuation(", source)
        self.assertIn(".empty_retry_available(", source)
        self.assertNotIn("state.evidence", source)
        self.assertNotIn("state.hypotheses", source)
        self.assertNotIn("state.endpoints", source)

    def test_dispatch_module_owns_orchestrator_todo_storage_access(self) -> None:
        queue_storage_modules = {"orchestrator/todo/queue.py"}
        offenders: list[str] = []
        for source_path in (PROJECT_ROOT / "killchain_docker/orchestrator").rglob(
            "*.py"
        ):
            relative = source_path.relative_to(
                PROJECT_ROOT / "killchain_docker"
            ).as_posix()
            if relative in queue_storage_modules:
                continue
            source = source_path.read_text()
            if _has_run_state_attr_access(source, "todos"):
                offenders.append(str(source_path.relative_to(PROJECT_ROOT)))
        for source_path in (PROJECT_ROOT / "killchain_docker/runtime").rglob("*.py"):
            source = source_path.read_text()
            if _has_state_attr_access(source, "todos", "rounds"):
                offenders.append(str(source_path.relative_to(PROJECT_ROOT)))
        self.assertEqual(offenders, [])

    def test_router_uses_projection_for_round_history(self) -> None:
        source = (PROJECT_ROOT / "killchain_docker/orchestrator/dispatch/router.py").read_text()
        self.assertIn(".router_round_summaries()", source)
        self.assertNotIn("state.rounds", source)

    def test_worker_agent_uses_projection_for_runtime_history(self) -> None:
        source = (PROJECT_ROOT / "killchain_docker/workers/runtime/agent.py").read_text()
        prompt_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/payload.py"
        ).read_text()
        context_source = (
            PROJECT_ROOT / "killchain_docker/workers/corrections/context.py"
        ).read_text()
        self.assertIn(".recent_failed_records(", prompt_source)
        self.assertIn(".recent_script_failure_context(", context_source)
        self.assertNotIn("state.execution_log", source)
        self.assertNotIn("state.evidence", source)
        self.assertNotIn("state.execution_log", prompt_source)
        self.assertNotIn("state.evidence", prompt_source)
        self.assertNotIn("state.execution_log", context_source)
        self.assertNotIn("state.evidence", context_source)

    def test_worker_package_root_contains_only_grouped_modules(self) -> None:
        root_files = sorted(
            path.name
            for path in WORKERS_ROOT.iterdir()
            if path.is_file() and path.suffix == ".py"
        )
        self.assertEqual(root_files, [])
        expected_groups = {
            "corrections",
            "execution",
            "personas",
            "prompts",
            "results",
            "runtime",
            "tooling",
        }
        actual_groups = {
            path.name
            for path in WORKERS_ROOT.iterdir()
            if path.is_dir() and not path.name.startswith("__")
        }
        self.assertEqual(actual_groups, expected_groups)

    def test_worker_execution_policies_are_split_from_worker_loop(self) -> None:
        worker_source = (
            PROJECT_ROOT / "killchain_docker/workers/runtime/worker.py"
        ).read_text()
        intent_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/intent.py"
        ).read_text()
        execution_policy_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/policy.py"
        ).read_text()
        self.assertIn("is_execution_closure_task", result_source := (
            PROJECT_ROOT / "killchain_docker/workers/results/assembly.py"
        ).read_text())
        self.assertIn("run_worker_tool_loop(", worker_source)
        for forbidden in (
            "def _is_flag_recovery_task",
            "def _is_execution_closure_task",
            "def _artifact_triage_intent_is_direct",
            "def _should_continue_after_step",
            "SCRIPT_REPAIRABLE_FAILURE_KINDS",
            "def _tool_success",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, worker_source)
        self.assertIn("def is_flag_recovery_task", intent_source)
        self.assertIn("def artifact_triage_intent_is_direct", intent_source)
        self.assertIn("def should_continue_after_step", execution_policy_source)
        self.assertIn("def tool_success", execution_policy_source)
        self.assertIn("is_execution_closure_task(todo)", result_source)

    def test_flag_validation_policy_is_not_worker_private_state(self) -> None:
        worker_source = (
            PROJECT_ROOT / "killchain_docker/workers/runtime/worker.py"
        ).read_text()
        background_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/background_flags.py"
        ).read_text()
        policy_source = (
            PROJECT_ROOT / "killchain_docker/workers/results/flag_validation.py"
        ).read_text()
        self.assertIn("flag_validation_result", worker_source)
        self.assertIn("flag_matches", background_source)
        for forbidden in (
            "_flag_matches",
            "_default_flag_matches",
            "_unwrap_flag",
            "_extract_prefix",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, worker_source)
                self.assertNotIn(forbidden, background_source)
        self.assertIn("def flag_validation_result", policy_source)
        self.assertIn("def flag_matches", policy_source)

    def test_dispatch_profiles_do_not_accept_legacy_aliases_or_unknown_profiles(
        self,
    ) -> None:
        self.assertEqual(normalize_dispatch_profile("binary-static"), "open")
        self.assertEqual(normalize_dispatch_profile("source_review"), "open")
        self.assertEqual(normalize_dispatch_profile("crypto_model"), "open")
        self.assertEqual(normalize_dispatch_profile("generic"), "open")
        self.assertEqual(normalize_dispatch_profile("todo"), "open")
        self.assertEqual(normalize_dispatch_profile("task"), "open")
        self.assertIsNone(dispatch_profile_spec("binary-static"))
        self.assertEqual(worker_preferences_for_profile("binary-static"), ())

    def test_dispatch_intent_drops_profiles_not_owned_by_catalog(self) -> None:
        for profile in ("source_review", "binary_static", "crypto_model", "other"):
            with self.subTest(profile=profile):
                intent = DispatchIntent.from_context(
                    {"dispatch_intent": {"profile": profile}}
                )
                self.assertEqual(intent.profile, "open")

    def test_dispatch_intent_never_promotes_unknown_family_to_profile(self) -> None:
        intent = DispatchIntent.from_context({"family": "custom-family"})
        self.assertEqual(intent.profile, "open")

    def test_dispatch_intent_does_not_rewrite_declared_dispatch_profile(self) -> None:
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.todo_intent")
        )
        intent = DispatchIntent.from_context(
            {
                "family": "binary-dynamic",
                "dispatch_intent": {
                    "profile": "scope_mapping",
                    "required_capability": "shell.exec",
                },
            }
        )
        self.assertEqual(intent.profile, "scope_mapping")

    def test_dispatch_intent_drops_unstructured_target_refs(self) -> None:
        intent = DispatchIntent.from_context(
            {
                "path": "/home/ctfplayer/ctf_files/artifact.bin",
                "scope": "tcp://target.example:31337",
                "dispatch_intent": {"target_refs": "artifact.bin"},
            }
        )
        self.assertEqual(intent.target_refs, {})

    def test_todo_phase_rejects_legacy_aliases(self) -> None:
        with self.assertRaises(ValueError):
            normalize_todo_phase("review")
        with self.assertRaises(ValueError):
            TodoItem(goal="Review source.", phase="triage")

    def test_memory_policy_rejects_partial_results(self) -> None:
        todo = TodoItem(goal="Recover the flag.")
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="artifact-worker",
            success=True,
            partial=True,
            summary="no candidate",
        )
        trusted = MemoryWritePolicy.trusted_worker_updates(
            todo, result, {"claim": "unguarded"}, require_candidate=True
        )
        self.assertEqual(trusted, {})

    def test_memory_write_policy_interface_does_not_depend_on_dispatch_profiles(
        self,
    ) -> None:
        signature = inspect.signature(MemoryWritePolicy.trusted_worker_updates)
        self.assertIn("require_candidate", signature.parameters)
        self.assertNotIn("execution_closure", signature.parameters)

    def test_worker_numeric_context_delegates_run_memory_projection(self) -> None:
        source = inspect.getsource(bounded_counter_candidates)
        self.assertIn(".numeric_hints(", source)
        self.assertNotIn(".recall()", source)
        self.assertNotIn("state.run_memory", source)
        self.assertNotIn("RunMemoryStore", source)

    def test_worker_agent_delegates_correction_policy(self) -> None:
        source = (PROJECT_ROOT / "killchain_docker/workers/runtime/agent.py").read_text()
        prompt_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/payload.py"
        ).read_text()
        context_source = (
            PROJECT_ROOT / "killchain_docker/workers/corrections/context.py"
        ).read_text()
        constraints_source = (
            PROJECT_ROOT / "killchain_docker/workers/corrections/constraints.py"
        ).read_text()
        counters_source = (
            PROJECT_ROOT / "killchain_docker/workers/corrections/counters.py"
        ).read_text()
        instructions_source = (
            PROJECT_ROOT / "killchain_docker/workers/corrections/instructions.py"
        ).read_text()
        self.assertIn("correction_context(", prompt_source)
        self.assertIn("execution_constraints(", prompt_source)
        for forbidden in (
            "def _correction_context",
            "def _execution_constraints",
            "def _bounded_counter_candidates",
            "def _script_correction_instruction",
            "def _recent_script_failure_context",
            "correction_context(",
            "execution_constraints(",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("def correction_context", context_source)
        self.assertIn("def execution_constraints", constraints_source)
        self.assertIn("def bounded_counter_candidates", counters_source)
        self.assertIn("def script_correction_instruction", instructions_source)
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/corrections/policy.py").exists()
        )

    def test_worker_execution_delegates_result_assembly_and_recon_assets(self) -> None:
        worker_source = (
            PROJECT_ROOT / "killchain_docker/workers/runtime/worker.py"
        ).read_text()
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/execution_loop.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/tool_execution_loop.py").exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/workers/base.py").exists())
        loop_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/loop.py"
        ).read_text()
        execution_policy_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/policy.py"
        ).read_text()
        direct_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/direct.py"
        ).read_text()
        step_source = (
            PROJECT_ROOT / "killchain_docker/workers/execution/step.py"
        ).read_text()
        enrichment_source = (
            PROJECT_ROOT / "killchain_docker/workers/results/enrichment.py"
        ).read_text()
        result_source = (
            PROJECT_ROOT / "killchain_docker/workers/results/assembly.py"
        ).read_text()
        recon_source = (
            PROJECT_ROOT / "killchain_docker/workers/results/recon.py"
        ).read_text()
        self.assertIn("run_direct_capability(", worker_source)
        self.assertIn("run_worker_tool_loop(", worker_source)
        self.assertNotIn("worker_result_from_bundle(", worker_source)
        self.assertNotIn("inject_recon_asset(", worker_source)
        self.assertNotIn("choose_tool_use(", worker_source)
        self.assertNotIn("def _result_from_bundle", worker_source)
        self.assertNotIn("def _inject_recon_asset", worker_source)
        self.assertNotIn("def _metadata_failure_kind", worker_source)
        self.assertNotIn("def _prepare_metadata", worker_source)
        self.assertNotIn("def _choose_capability", worker_source)
        self.assertNotIn("def _choose_fixed_capability", worker_source)
        self.assertNotIn("def _fixed_llm_capability", worker_source)
        self.assertNotIn("def _run_direct_capability", worker_source)
        self.assertNotIn("encoding_cascade", worker_source)
        self.assertNotIn("urlparse", worker_source)
        self.assertNotIn("INFRASTRUCTURE_FAILURE_KINDS", worker_source)
        self.assertNotIn("AssetKind.WEB_APPLICATION", worker_source)
        self.assertIn("def run_worker_tool_loop", loop_source)
        self.assertIn("run_tool_step(", loop_source)
        self.assertIn("worker_result_from_bundle(", loop_source)
        self.assertIn("enrich_worker_result(", loop_source)
        self.assertIn("should_continue_after_step(", execution_policy_source)
        self.assertIn("prepare_execution_metadata(", step_source)
        self.assertIn("def choose_capability", step_source)
        self.assertIn("def fixed_llm_capability", step_source)
        self.assertIn("def prepare_execution_metadata", step_source)
        self.assertIn("normalize_tool_metadata(", step_source)
        self.assertIn("urlparse", step_source)
        self.assertNotIn("inject_recon_asset(", loop_source)
        self.assertNotIn("encoding_cascade", loop_source)
        self.assertIn("def run_direct_capability", direct_source)
        self.assertIn("worker_result_from_bundle(", direct_source)
        self.assertIn("def enrich_worker_result", enrichment_source)
        self.assertIn("inject_recon_asset(", enrichment_source)
        self.assertIn("encoding_cascade", enrichment_source)
        self.assertIn("def worker_result_from_bundle", result_source)
        self.assertIn("INFRASTRUCTURE_FAILURE_KINDS", result_source)
        self.assertIn("def inject_recon_asset", recon_source)
        self.assertIn("AssetKind.WEB_APPLICATION", recon_source)

    def test_worker_agent_delegates_tool_use_prompt_construction(self) -> None:
        source = (
            PROJECT_ROOT / "killchain_docker/workers/runtime/tool_choice.py"
        ).read_text()
        choice_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/choice.py"
        ).read_text()
        fixed_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/fixed.py"
        ).read_text()
        payload_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/payload.py"
        ).read_text()
        rules_source = (
            PROJECT_ROOT / "killchain_docker/workers/prompts/rules.py"
        ).read_text()
        self.assertIn("build_tool_choice_prompt", source)
        self.assertIn("build_fixed_tool_prompt", source)
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/prompts/tool_use.py").exists()
        )
        for forbidden in (
            "def _tool_use_rules",
            "tool_catalog",
            "EvidenceContextBuilder",
            "prompt_worker_todo",
            "tool_metadata_contract",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("def build_tool_choice_prompt", choice_source)
        self.assertIn("tool_choice_payload(", choice_source)
        self.assertIn("script_reminder(", choice_source)
        self.assertIn("def build_fixed_tool_prompt", fixed_source)
        self.assertIn("fixed_tool_payload(", fixed_source)
        self.assertIn("EvidenceContextBuilder", payload_source)
        self.assertIn("prompt_worker_todo", payload_source)
        self.assertIn("correction_context(", payload_source)
        self.assertIn("execution_constraints(", payload_source)
        self.assertIn("def tool_use_rules", rules_source)

    def test_tool_metadata_delegates_contracts_and_script_metadata(self) -> None:
        source = (
            PROJECT_ROOT / "killchain_docker/workers/tooling/metadata/router.py"
        ).read_text()
        artifact_source = (
            PROJECT_ROOT / "killchain_docker/workers/tooling/metadata/artifact.py"
        ).read_text()
        contracts_source = (
            PROJECT_ROOT / "killchain_docker/workers/tooling/contracts/catalog.py"
        ).read_text()
        script_source = (
            PROJECT_ROOT / "killchain_docker/workers/tooling/metadata/script.py"
        ).read_text()
        self.assertIn("normalize_script_metadata", source)
        self.assertIn("TOOL_METADATA_CONTRACT_CATALOG", source)
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/tooling/metadata.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/tooling/contracts.py").exists()
        )
        self.assertIn("def normalize_disk_extract_metadata", artifact_source)
        self.assertIn("def normalize_media_scan_metadata", artifact_source)
        for forbidden in (
            "TOOL_METADATA_CONTRACT_CATALOG: dict",
            "def tool_metadata_contract",
            "def _normalize_disk_extract",
            "def _normalize_media_scan",
            "PythonScratchLiteralRewriter",
            "def _normalize_script",
            "def _rewrite_python_scratch_literals",
            "def _validate_python_script",
            "def _normalize_script_language",
            "ast.",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertIn("TOOL_METADATA_CONTRACT_CATALOG: dict", contracts_source)
        self.assertIn("def tool_metadata_contract", contracts_source)
        self.assertIn("SHELL_TOOL_METADATA_CONTRACTS", contracts_source)
        self.assertIn("WEB_TOOL_METADATA_CONTRACTS", contracts_source)
        self.assertIn("ARTIFACT_TOOL_METADATA_CONTRACTS", contracts_source)
        self.assertIn("BINARY_TOOL_METADATA_CONTRACTS", contracts_source)
        self.assertIn("RECOVERY_TOOL_METADATA_CONTRACTS", contracts_source)
        self.assertIn("def normalize_script_metadata", script_source)
        self.assertIn("def rewrite_python_scratch_literals", script_source)
        self.assertIn("class PythonScratchLiteralRewriter", script_source)
        self.assertIn("def validate_python_script", script_source)
        self.assertIn("def normalize_script_language", script_source)

    def test_scheduler_selects_only_earliest_phase(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        recon = queue.enqueue(TodoItem(goal="Map", phase=TodoPhase.RECON, priority=10))
        queue.enqueue(TodoItem(goal="Exploit", phase=TodoPhase.EXPLOIT, priority=100))
        batch = select_ready_batch(queue, max_assignments=5)
        self.assertEqual(batch.focus_phase, TodoPhase.RECON)
        self.assertEqual([todo.todo_id for todo in batch.todos], [recon.todo_id])

    def test_todo_queue_owns_run_state_todo_behavior(self) -> None:
        state = RunState(objective="Solve.")
        todos = TodoQueue(state)
        first = todos.enqueue(TodoItem(goal="Review notes."))
        duplicate = todos.enqueue(TodoItem(goal="Review notes."))
        self.assertIs(first, duplicate)
        self.assertEqual(todos.get(first.todo_id), first)
        self.assertEqual(todos.ready(), [first])
        self.assertTrue(todos.has_open())
        self.assertFalse(hasattr(RunState, "queue_todo"))
        self.assertFalse(hasattr(RunState, "ready_todos"))
        self.assertFalse(hasattr(RunState, "has_open_todos"))
        self.assertFalse(hasattr(RunState, "get_todo"))
        self.assertFalse(hasattr(RunState, "interrupt_running_todos"))
        self.assertFalse(hasattr(RunState, "touch"))
        self.assertFalse(hasattr(RunState, "_enforce_caps"))

    def test_run_state_maintenance_owns_touch_and_caps(self) -> None:
        source_paths = [
            "killchain_docker/orchestrator/todo/queue.py",
            "killchain_docker/orchestrator/closure/controller.py",
            "killchain_docker/orchestrator/run_termination.py",
            "killchain_docker/orchestrator/runtime_events.py",
            "killchain_docker/state/artifact_store.py",
            "killchain_docker/state/candidate_facts.py",
            "killchain_docker/state/evidence_facts.py",
            "killchain_docker/state/execution_facts.py",
            "killchain_docker/state/recon_facts.py",
            "killchain_docker/state/journal.py",
            "killchain_docker/state/outcome.py",
            "killchain_docker/state/state_delta.py",
            "killchain_docker/state/worker_results.py",
        ]
        self.assertFalse(
            (
                PROJECT_ROOT / "killchain_docker/orchestrator/closure_execution.py"
            ).exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/run_control.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/dispatch_cycle.py").exists()
        )
        self.assertFalse(
            (
                PROJECT_ROOT / "killchain_docker/orchestrator/planning/refresh.py"
            ).exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/round_outcome.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/progress_policy.py").exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/state/facts.py").exists())
        for source_path in source_paths:
            with self.subTest(source_path=source_path):
                source = (PROJECT_ROOT / source_path).read_text()
                self.assertNotIn("state.touch()", source)
                self.assertNotIn("self.state.touch()", source)
        model_source = (
            PROJECT_ROOT / "killchain_docker/state/run_state.py"
        ).read_text()
        maintenance_source = (
            PROJECT_ROOT / "killchain_docker/state/maintenance.py"
        ).read_text()
        self.assertNotIn("def touch", model_source)
        self.assertNotIn("def _enforce_caps", model_source)
        self.assertIn("def touch", maintenance_source)
        self.assertIn("def enforce_caps", maintenance_source)

    def test_todo_lifecycle_owns_todo_status_writes(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Run lifecycle."))
        queue.start(todo, "runtime-worker")
        self.assertEqual(todo.status.value, "running")
        queue.release_transient(todo, "temporary LLM outage")
        self.assertEqual(todo.status.value, "pending")
        queue.start(todo, "runtime-worker")
        partial_result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="runtime-worker",
            success=False,
            summary="diagnostic evidence",
            partial=True,
            partial_reason="no flag yet",
        )
        queue.apply_result(todo, partial_result)
        self.assertEqual(todo.status.value, "pending")
        self.assertEqual(todo.error, "no flag yet")
        queue.start(todo, "runtime-worker")
        queue.apply_result(todo, partial_result)
        self.assertEqual(todo.status.value, "partial")
        self.assertEqual(todo.error, "no flag yet")
        queue.block(todo, "terminal path")
        self.assertEqual(todo.status.value, "blocked")
        self.assertTrue(queue.has_terminal_unsolved())
        self.assertEqual(queue.terminal_unsolved_reason(), "todo_blocked")
        second = queue.enqueue(TodoItem(goal="Second lifecycle.", dedupe_key="second"))
        queue.start(second, "runtime-worker")
        self.assertEqual(
            queue.halt_for_transient_error("temporary outage", todo=second), 1
        )
        self.assertEqual(second.status.value, "interrupted")
        queue.start(second, "runtime-worker")
        self.assertEqual(queue.fail_running("runtime failure"), 1)
        self.assertEqual(second.status.value, "failed")
        self.assertEqual(queue.terminal_unsolved_reason(), "todo_failed")
        self.assertFalse(hasattr(TodoItem, "is_ready"))
        self.assertFalse(hasattr(TodoItem, "mark_running"))
        self.assertFalse(hasattr(TodoItem, "mark_completed"))
        self.assertFalse(hasattr(TodoItem, "mark_partial"))
        self.assertFalse(hasattr(TodoItem, "mark_failed"))
        self.assertFalse(hasattr(TodoItem, "release_after_transient_error"))
        self.assertFalse(hasattr(TodoItem, "mark_blocked"))
        self.assertFalse(hasattr(TodoItem, "mark_interrupted"))
        runtime_source_paths = [
            "killchain_docker/state/worker_results.py",
            "killchain_docker/orchestrator/execution.py",
        ]
        forbidden_calls = (
            ".mark_running(",
            ".mark_completed(",
            ".mark_partial(",
            ".mark_failed(",
            ".release_after_transient_error(",
            ".mark_blocked(",
            ".mark_interrupted(",
        )
        for source_path in runtime_source_paths:
            with self.subTest(source_path=source_path):
                text = (PROJECT_ROOT / source_path).read_text()
                self.assertIn("Todo", text)
                for call in forbidden_calls:
                    self.assertNotIn(call, text)
        direct_status_writes = []
        for source_path in (PROJECT_ROOT / "killchain_docker").rglob("*.py"):
            if source_path.as_posix().endswith("orchestrator/todo/queue.py"):
                continue
            tree = ast.parse(source_path.read_text())
            for node in ast.walk(tree):
                targets = []
                if isinstance(node, ast.Assign):
                    targets = list(node.targets)
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                elif isinstance(node, ast.AugAssign):
                    targets = [node.target]
                for target in targets:
                    if (
                        isinstance(target, ast.Attribute)
                        and target.attr == "status"
                        and isinstance(target.value, ast.Name)
                        and (target.value.id == "todo")
                    ):
                        direct_status_writes.append(
                            f"{source_path.relative_to(PROJECT_ROOT)}:{target.lineno}"
                        )
        self.assertEqual(direct_status_writes, [])
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.task_queue")
        )
        execution_source = "\n".join(
            (
                (PROJECT_ROOT / source_path).read_text()
                for source_path in (
                    "killchain_docker/orchestrator/execution.py",
                    "killchain_docker/orchestrator/dispatch/controller.py",
                )
            )
        )
        self.assertFalse(_has_run_state_attr_access(execution_source, "todos"))
        self.assertNotIn("def terminal_unsolved_reason", execution_source)
        self.assertNotIn("todo.status == TodoStatus.FAILED", execution_source)
        self.assertNotIn("todo.status == TodoStatus.BLOCKED", execution_source)
        self.assertNotIn("todo.status == TodoStatus.PARTIAL", execution_source)

    def test_partial_result_repends_until_retry_budget_exhausted(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Recover flag.", max_attempts=2))
        partial_result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="runtime-worker",
            success=True,
            summary="script ran but no flag",
            partial=True,
            partial_reason="no flag candidate yet",
        )
        queue.start(todo, "runtime-worker")
        queue.apply_result(todo, partial_result)
        self.assertEqual(todo.status, TodoStatus.PENDING)
        self.assertIsNone(todo.assigned_worker)
        self.assertEqual(todo.attempts, 1)
        self.assertEqual(todo.error, "no flag candidate yet")
        queue.start(todo, "runtime-worker")
        queue.apply_result(todo, partial_result)
        self.assertEqual(todo.status, TodoStatus.PARTIAL)
        self.assertEqual(todo.attempts, 2)
        self.assertEqual(queue.terminal_unsolved_reason(), "partial_todos_unsolved")

    def test_worker_identity_uses_persona_spec_not_protocol_adapter(self) -> None:
        from killchain_docker.workers.personas.catalog import PersonaSpec
        from killchain_docker.workers.runtime.worker import Worker

        type_hints = get_type_hints(Worker.__init__)
        self.assertIs(type_hints["persona"], PersonaSpec)
        worker_source = (
            PROJECT_ROOT / "killchain_docker/workers/runtime/worker.py"
        ).read_text()
        self.assertNotIn("@name.setter", worker_source)
        self.assertNotIn("def name(self, value", worker_source)
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.workers.protocols")
        )
        self.assertIsNone(importlib.util.find_spec("killchain_docker.workers.routing"))
        self.assertIsNone(importlib.util.find_spec("killchain_docker.workers.persona"))
        self.assertIsNone(importlib.util.find_spec("killchain_docker.workers.specs"))
        self.assertIsNone(importlib.util.find_spec("killchain_docker._compat"))
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.state.file_classification")
        )
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.policy")
        )
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.agents")
        )
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.execution_events")
        )
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.execution_results")
        )
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.todo_policy")
        )
        self.assertIsNone(importlib.util.find_spec("killchain_docker.state.models"))
        self.assertIsNone(importlib.util.find_spec("killchain_docker.state.memory"))
        self.assertIsNone(importlib.util.find_spec("killchain_docker.controller"))
        self.assertFalse((PROJECT_ROOT / "killchain_docker/state/__init__.py").exists())
        self.assertFalse((PROJECT_ROOT / "killchain_docker/controller.py").exists())
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/__init__.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/dispatch.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/policy.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/agents.py").exists()
        )
        self.assertFalse(
            (
                PROJECT_ROOT / "killchain_docker/orchestrator/execution_events.py"
            ).exists()
        )
        self.assertFalse(
            (
                PROJECT_ROOT / "killchain_docker/orchestrator/execution_results.py"
            ).exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/orchestrator/todo_policy.py").exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/state/models.py").exists())
        self.assertFalse((PROJECT_ROOT / "killchain_docker/state/memory.py").exists())
        self.assertFalse(
            (
                PROJECT_ROOT / "killchain_docker/orchestrator/planning/__init__.py"
            ).exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/tools/__init__.py").exists())
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/tools/plugins/__init__.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/workers/__init__.py").exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/llm/__init__.py").exists())
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/knowledge/__init__.py").exists()
        )
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/reasoning/__init__.py").exists()
        )
        self.assertFalse((PROJECT_ROOT / "killchain_docker/batch/__init__.py").exists())
        self.assertFalse(
            (PROJECT_ROOT / "killchain_docker/prompts/__init__.py").exists()
        )

    def test_todo_status_commands_block_open_todos_for_dispatch_terminal_paths(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        pending = queue.enqueue(TodoItem(goal="Pending."))
        running = queue.enqueue(TodoItem(goal="Running.", dedupe_key="running"))
        _todo_queue(state).start(running, "runtime-worker")
        completed = queue.enqueue(TodoItem(goal="Done.", dedupe_key="done"))
        _todo_queue(state).complete(completed, "done")
        blocked = queue.block_open("router_no_assignments")
        self.assertEqual(blocked, 2)
        self.assertEqual(pending.status.value, "blocked")
        self.assertEqual(running.status.value, "blocked")
        self.assertEqual(completed.status.value, "completed")

    def test_specific_fact_stores_own_typed_fact_upserts(self) -> None:
        state = RunState(objective="Solve.")
        artifacts = ArtifactFactStore(state)
        candidates = FlagCandidateStore(state)
        evidence = EvidenceFactStore(state)
        execution = ExecutionFactStore(state)
        recon = ReconFactStore(state)
        first_artifact = Artifact(
            artifact_id="artifact-a",
            path="/home/ctfplayer/ctf_files/blob.bin",
            kind="unknown",
        )
        second_artifact = Artifact(
            artifact_id="artifact-b",
            path="/home/ctfplayer/ctf_files/blob.bin",
            kind="binary",
            digest="sha256:abc",
        )
        artifacts.artifact(first_artifact)
        artifacts.artifact(second_artifact)
        evidence.evidence(
            EvidenceRecord(
                evidence_id="evidence-1",
                task_id="todo-1",
                tool_name="script_exec",
                mode="local_command",
                summary="first",
            )
        )
        evidence.evidence(
            EvidenceRecord(
                evidence_id="evidence-1",
                task_id="todo-1",
                tool_name="script_exec",
                mode="local_command",
                summary="second",
            )
        )
        execution.endpoint(Endpoint(endpoint_id="endpoint-1", url="http://target/"))
        execution.endpoint(Endpoint(endpoint_id="endpoint-1", title="home"))
        execution.route(
            Route(route_id="route-1", url="http://target/login", path="/login")
        )
        execution.hypothesis(
            Hypothesis(hypothesis_id="hyp-1", title="SQLi", confidence=0.3)
        )
        execution.hypothesis(
            Hypothesis(hypothesis_id="hyp-1", title="SQLi", confidence=0.9)
        )
        execution.vulnerability(
            Vulnerability(vulnerability_id="vuln-1", title="SQL injection")
        )
        execution.exploit_attempt(
            ExploitAttempt(attempt_id="attempt-1", technique="sqlmap")
        )
        execution.session(Session(session_id="session-1", username="ctf"))
        candidates.flag_candidate(
            FlagCandidate(candidate_id="candidate-1", value="flag{one}", confidence=0.2)
        )
        candidates.flag_candidate(
            FlagCandidate(candidate_id="candidate-2", value="flag{one}", confidence=0.8)
        )
        removed = candidates.remove_by_value("flag{one}")
        candidates.flag_candidate(
            FlagCandidate(candidate_id="candidate-3", value="flag{two}")
        )
        recon.network_edges(
            [NetworkEdge(source="target", target="port-80", relationship="exposes")]
        )
        self.assertEqual(len(state.artifacts), 1)
        self.assertEqual(state.artifacts["artifact-a"].kind, "binary")
        self.assertEqual(state.endpoints["endpoint-1"].title, "home")
        self.assertEqual(state.routes["route-1"].path, "/login")
        self.assertEqual(state.hypotheses["hyp-1"].confidence, 0.9)
        self.assertEqual(state.vulnerabilities["vuln-1"].title, "SQL injection")
        self.assertEqual(state.exploit_attempts["attempt-1"].task_id, "")
        self.assertEqual(state.sessions["session-1"].username, "ctf")
        self.assertEqual(removed, 1)
        self.assertEqual(list(state.flag_candidates), ["candidate-3"])
        self.assertEqual(state.network_edges[0].relationship, "exposes")
        self.assertEqual(state.evidence["evidence-1"].summary, "second")
        self.assertFalse(hasattr(RunState, "upsert_asset"))
        self.assertFalse(hasattr(RunState, "upsert_finding"))
        self.assertFalse(hasattr(RunState, "upsert_credential"))
        self.assertFalse(hasattr(RunState, "upsert_evidence"))
        for model_type in (
            Artifact,
            Endpoint,
            EvidenceRecord,
            ExploitAttempt,
            FlagCandidate,
            Hypothesis,
            Route,
            Session,
            Vulnerability,
        ):
            self.assertFalse(hasattr(model_type, "merge"), model_type.__name__)
        merge_source = (
            PROJECT_ROOT / "killchain_docker/state/fact_merges.py"
        ).read_text()
        models_source = "\n".join(
            [
                (PROJECT_ROOT / "killchain_docker/state/domain.py").read_text(),
                (PROJECT_ROOT / "killchain_docker/state/todos.py").read_text(),
                (PROJECT_ROOT / "killchain_docker/state/run_state.py").read_text(),
            ]
        )
        self.assertIn("def merge_artifact", merge_source)
        self.assertIn("def merge_evidence", merge_source)
        self.assertNotIn(".merge(", merge_source)
        self.assertNotIn("def merge", models_source)

    def test_state_appliers_delegate_fact_storage_to_specific_stores(self) -> None:
        delta_source = inspect.getsource(StateDeltaApplier.apply)
        candidate_source = inspect.getsource(StateDeltaApplier._apply_flag_candidate)
        worker_source = inspect.getsource(WorkerResultApplier.apply)
        self.assertIn("self.artifacts.artifact", delta_source)
        self.assertIn("self.execution_facts.endpoint", delta_source)
        self.assertIn("self.candidates.flag_candidate", candidate_source)
        self.assertIn("self.recon_facts.network_edges", worker_source)
        for direct_write in (
            "self.state.artifacts[",
            "self.state.endpoints[",
            "self.state.routes[",
            "self.state.flag_candidates",
            "self.state.hypotheses[",
            "self.state.vulnerabilities[",
            "self.state.exploit_attempts[",
            "self.state.sessions[",
            "self.state.network_edges",
        ):
            self.assertNotIn(direct_write, delta_source)
            self.assertNotIn(direct_write, candidate_source)
            self.assertNotIn(direct_write, worker_source)

    def test_run_outcome_store_owns_terminal_state_writes(self) -> None:
        state = RunState(objective="Solve.")
        outcome = RunOutcomeStore(state)
        outcome.start()
        self.assertEqual(state.status, RunStatus.RUNNING)
        outcome.failed("router_no_assignments")
        self.assertEqual(state.status, RunStatus.FAILED)
        self.assertEqual(state.stop_reason, "router_no_assignments")
        outcome.solved(validated_flag="flag{ok}", reason="background_flag_validated")
        self.assertTrue(state.solved)
        self.assertEqual(state.status, RunStatus.SOLVED)
        self.assertEqual(state.validated_flag, "flag{ok}")
        runtime_source_paths = [
            "killchain_docker/orchestrator/execution.py",
            "killchain_docker/orchestrator/dispatch/controller.py",
            "killchain_docker/orchestrator/planning/cycle_controller.py",
            "killchain_docker/runtime/session.py",
            "killchain_docker/runtime/persistence.py",
            "killchain_docker/state/worker_results.py",
        ]
        forbidden_fields = {
            "status",
            "stop_reason",
            "solved",
            "validated_flag",
            "last_cycle_at",
        }
        for source_path in runtime_source_paths:
            with self.subTest(source_path=source_path):
                text = (PROJECT_ROOT / source_path).read_text()
                tree = ast.parse(text)
                for node in ast.walk(tree):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                        continue
                    targets = (
                        node.targets if isinstance(node, ast.Assign) else [node.target]
                    )
                    for target in targets:
                        if (
                            isinstance(target, ast.Attribute)
                            and target.attr in forbidden_fields
                        ):
                            value = target.value
                            if isinstance(value, ast.Name) and value.id == "state":
                                self.fail(f"{source_path} writes state.{target.attr}")
                            if (
                                isinstance(value, ast.Attribute)
                                and value.attr == "state"
                                and isinstance(value.value, ast.Name)
                                and (value.value.id == "self")
                            ):
                                self.fail(
                                    f"{source_path} writes self.state.{target.attr}"
                                )

    def test_run_progress_controller_owns_forced_pivot_tracking(self) -> None:
        state = RunState(objective="Solve.")
        events: list[tuple[str, dict[str, object]]] = []
        controller = RunProgressController(
            state=state, events=self._runtime_events(state, events), threshold=2
        )
        no_progress = WorkerResult(
            todo_id="todo-1",
            worker_name="runtime-worker",
            success=False,
            summary="timeout",
            result_quality="timeout",
        )
        first = controller.observe_round(cycle=1, results=[no_progress])
        second = controller.observe_round(cycle=2, results=[no_progress])
        self.assertFalse(first)
        self.assertTrue(second)
        self.assertEqual(controller.rounds_without_progress, 0)
        self.assertEqual(controller.pivot_count, 1)
        self.assertEqual(state.metadata["forced_pivot"]["pivot_number"], 1)
        self.assertIn("FORCED PIVOT #1", events[-1][0])

    def test_runtime_metadata_writes_use_metadata_store(self) -> None:
        source_paths = [
            "killchain_docker/orchestrator/progress/run_progress.py",
            "killchain_docker/orchestrator/run_termination.py",
            "killchain_docker/state/outcome.py",
        ]
        forbidden = (
            'metadata["last_llm_error"]',
            "metadata['last_llm_error']",
            'metadata["forced_pivot"]',
            "metadata['forced_pivot']",
            'metadata["runtime_error"]',
            "metadata['runtime_error']",
            '.metadata.pop("forced_pivot"',
            ".metadata.pop('forced_pivot'",
        )
        for source_path in source_paths:
            with self.subTest(source_path=source_path):
                source = (PROJECT_ROOT / source_path).read_text()
                self.assertIn("RunMetadataStore", source)
                for pattern in forbidden:
                    self.assertNotIn(pattern, source)

    def test_runtime_status_uses_projection_for_runtime_metadata(self) -> None:
        source = "\n".join(
            [
                (PROJECT_ROOT / "killchain_docker/runtime/compact_log.py").read_text(),
                (PROJECT_ROOT / "killchain_docker/runtime/persistence.py").read_text(),
            ]
        )
        self.assertIn(".runtime_error_payload()", source)
        self.assertIn(".payload()", source)
        self.assertIn(".name()", source)
        self.assertIn(".rag_payload()", source)
        self.assertIn("RunReportProjection", source)
        self.assertNotIn("state.metadata", source)

    def test_orchestrator_cycle_entry_gate_halts_when_solved(self) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        begin_source = inspect.getsource(Orchestrator._begin_cycle)
        self.assertNotIn("last_cycle_at", run_source)
        self.assertIn("_begin_cycle", run_source)
        self.assertIn("sync_background_flags", begin_source)
        self.assertIn("validated flag found", begin_source)
        self.assertIn("cycle_started", begin_source)

    def test_scheduler_waits_for_todo_dependencies(self) -> None:
        state = RunState(objective="Solve.")
        upstream = _todo_queue(state).enqueue(
            TodoItem(goal="Inventory", phase=TodoPhase.RECON, dedupe_key="inventory")
        )
        downstream = _todo_queue(state).enqueue(
            TodoItem(
                goal="Analyze inventory output",
                phase=TodoPhase.RECON,
                priority=100,
                depends_on=["inventory"],
            )
        )
        queue = _todo_queue(state)
        batch = select_ready_batch(queue, max_assignments=5)
        self.assertEqual([todo.todo_id for todo in batch.todos], [upstream.todo_id])
        self.assertEqual(
            [todo.todo_id for todo in batch.blocked_by_dependency], [downstream.todo_id]
        )
        _todo_queue(state).complete(upstream, "done")
        batch = select_ready_batch(queue, max_assignments=5)
        self.assertEqual([todo.todo_id for todo in batch.todos], [downstream.todo_id])
        self.assertEqual(
            queue.dependency_check(downstream).state, DependencyState.SATISFIED
        )

    def test_todo_queue_writer_reports_created_and_deduped_planner_todos(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = TodoItem(goal="Map", phase=TodoPhase.RECON, dedupe_key="map")
        first = queue.enqueue(todo)
        second = queue.enqueue(TodoItem(goal="Map again", dedupe_key="map"))
        self.assertEqual(first.todo_id, second.todo_id)
        self.assertTrue(queue.has_ready())
        _todo_queue(state).complete(first, "mapped")
        self.assertFalse(queue.has_ready())
        self.assertFalse(queue.has_open())

    def test_planning_refresh_controller_owns_planner_to_queue_writes(self) -> None:
        state = RunState(objective="Solve.")
        events: list[str] = []
        planner = _RefreshPlanner(
            PlannerDecision(
                summary="seed one todo",
                todos=[
                    PlannedTodo(
                        goal="Map scope.", phase=TodoPhase.RECON, dedupe_key="map-scope"
                    )
                ],
                notes=["note one"],
                stop_run=True,
            )
        )
        controller = PlanningRefreshController(
            state=state,
            planner=planner,
            todos=_todo_queue(state),
            journal=RunJournal(state),
            emit=events.append,
        )
        result = controller.refresh(cycle=3)
        self.assertEqual(planner.calls, 1)
        self.assertEqual(result.summary, "seed one todo")
        self.assertEqual(result.proposed, 1)
        self.assertEqual(result.created, 1)
        self.assertEqual(result.deduped, 0)
        self.assertTrue(result.stop_run)
        self.assertEqual(state.todos[0].dedupe_key, "map-scope")
        self.assertEqual(state.orchestration_notes, ["note one"])
        self.assertIn("[cycle 3] plan: proposed=1 new=1", events[0])
        self.assertFalse(hasattr(Orchestrator, "_queue_planner_decision"))
        self.assertFalse(hasattr(Orchestrator, "refresh_plan"))
        self.assertFalse(hasattr(Orchestrator, "refresh_deterministic_seeds"))

    def test_planning_refresh_controller_filters_missing_dependency_refs(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        controller = PlanningRefreshController(
            state=state,
            planner=_RefreshPlanner(
                PlannerDecision(
                    summary="dependent plan",
                    todos=[
                        PlannedTodo(
                            goal="Use an upstream result.",
                            phase=TodoPhase.ANALYSIS,
                            dedupe_key="dependent-work",
                            depends_on=["missing-upstream"],
                        )
                    ],
                )
            ),
            todos=_todo_queue(state),
            journal=RunJournal(state),
            emit=lambda _message: None,
        )
        result = controller.refresh(cycle=1)
        self.assertEqual(result.proposed, 1)
        self.assertEqual(result.created, 0)
        self.assertEqual(state.todos, [])
        self.assertTrue(
            any(
                ("dependency gate dropped" in note)
                for note in state.orchestration_notes
            )
        )

    def test_planning_cycle_controller_owns_ready_backlog_seed_refresh(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        queue.enqueue(TodoItem(goal="Ready.", dedupe_key="ready"))
        events: list[tuple[str, dict[str, object]]] = []
        controller = PlanningCycleController(
            state=state,
            todos=queue,
            refresh=PlanningRefreshController(
                state=state,
                planner=_RefreshPlanner(PlannerDecision(summary="unused")),
                todos=queue,
                journal=RunJournal(state),
                emit=lambda _message: None,
            ),
            events=self._runtime_events(state, events),
            termination=_NoopTermination(),
        )
        result = controller.plan(cycle=8)
        self.assertFalse(result.halt_run)
        self.assertFalse(result.retry_cycle)
        self.assertEqual(result.summary, "planner skipped: ready todo backlog")
        self.assertEqual(events[0][0], "[cycle 8] planner skipped - ready todo backlog")

    def test_ready_backlog_after_transient_skip_does_not_seed_refresh(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        queue.enqueue(TodoItem(goal="Ready.", dedupe_key="ready"))
        state.metadata["last_transient_skip"] = {
            "cycle": 7,
            "source": "artifact-worker",
            "schema_name": "ToolUseDecision",
        }
        events: list[tuple[str, dict[str, object]]] = []
        planner = _RefreshPlanner(PlannerDecision(summary="unused"))
        planner.pipeline = _TransientBacklogSeedPipeline()
        controller = PlanningCycleController(
            state=state,
            todos=queue,
            refresh=PlanningRefreshController(
                state=state,
                planner=planner,
                todos=queue,
                journal=RunJournal(state),
                emit=lambda message: events.append((message, {})),
            ),
            events=self._runtime_events(state, events),
            termination=_NoopTermination(),
        )
        result = controller.plan(cycle=8)
        self.assertEqual(result.summary, "planner skipped: ready todo backlog")
        self.assertEqual(planner.pipeline.calls, 0)
        self.assertEqual(len(state.todos), 1)
        self.assertNotIn("last_transient_skip", state.metadata)
        self.assertFalse(
            any(("deterministic seed refresh" in message for message, _ in events))
        )

    def test_planning_cycle_controller_owns_planner_stop_transition(self) -> None:
        state = RunState(objective="Solve.")
        events: list[tuple[str, dict[str, object]]] = []
        checkpoints: list[bool] = []
        queue = _todo_queue(state)
        controller = PlanningCycleController(
            state=state,
            todos=queue,
            refresh=PlanningRefreshController(
                state=state,
                planner=_RefreshPlanner(PlannerDecision(summary="stop", stop_run=True)),
                todos=queue,
                journal=RunJournal(state),
                emit=lambda _message: None,
            ),
            events=self._runtime_events(state, events, checkpoints),
            termination=_NoopTermination(),
        )
        result = controller.plan(cycle=9)
        self.assertTrue(result.halt_run)
        self.assertEqual(result.summary, "stop")
        self.assertEqual(state.status.value, "stopped")
        self.assertEqual(state.stop_reason, "planner_stop")
        self.assertIn("planner signalled stop", events[-1][0])
        self.assertTrue(checkpoints)

    def test_orchestrator_delegates_planning_cycle(self) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        self.assertNotIn("planner skipped - ready todo backlog", run_source)
        self.assertNotIn("planning next todos", run_source)
        self.assertNotIn("planner signalled stop", run_source)
        self.assertNotIn("planner LLM error", run_source)
        self.assertNotIn("refresh_deterministic_seeds", run_source)
        self.assertIn("_planning_cycle_controller.plan", run_source)

    def test_todo_status_commands_block_unsatisfiable_dependencies(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        missing = _todo_queue(state).enqueue(
            TodoItem(goal="Use missing upstream", depends_on=["missing-key"])
        )
        failed = _todo_queue(state).enqueue(
            TodoItem(goal="Failed upstream", dedupe_key="failed-upstream")
        )
        _todo_queue(state).fail(failed, "no evidence", retryable=False)
        blocked = _todo_queue(state).enqueue(
            TodoItem(goal="Use failed upstream", depends_on=["failed-upstream"])
        )
        self.assertEqual(
            queue.dependency_check(missing).state, DependencyState.UNSATISFIABLE
        )
        self.assertEqual(
            queue.dependency_check(blocked).state, DependencyState.UNSATISFIABLE
        )
        blocked_items = queue.block_unsatisfiable_dependencies()
        self.assertEqual(
            [(block.todo.todo_id, block.reason) for block in blocked_items],
            [
                (missing.todo_id, "missing dependency 'missing-key'"),
                (
                    blocked.todo_id,
                    "dependency 'failed-upstream' ended with status failed",
                ),
            ],
        )
        self.assertEqual(missing.status.value, "blocked")
        self.assertEqual(blocked.status.value, "blocked")

    def test_todo_status_commands_keep_waiting_dependencies_pending(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        upstream = _todo_queue(state).enqueue(
            TodoItem(goal="Upstream", dedupe_key="upstream")
        )
        downstream = _todo_queue(state).enqueue(
            TodoItem(goal="Downstream", depends_on=["upstream"])
        )
        self.assertEqual(
            queue.dependency_check(downstream).state, DependencyState.WAITING
        )
        blocked_items = queue.block_unsatisfiable_dependencies()
        self.assertEqual(blocked_items, [])
        self.assertEqual(upstream.status.value, "pending")
        self.assertEqual(downstream.status.value, "pending")

    def test_assignment_planner_owns_structural_and_llm_assignment_validation(
        self,
    ) -> None:
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.orchestrator.routing_policy")
        )
        state = RunState(objective="Solve.")
        flag = _todo_queue(state).enqueue(
            TodoItem(goal="Validate candidate.", phase=TodoPhase.FLAG_VALIDATION)
        )
        generic = _todo_queue(state).enqueue(TodoItem(goal="Review notes."))
        directory = AgentDirectory.from_workers(
            [_RuntimeWorker("flag-worker"), _RuntimeWorker("artifact-worker")]
        )
        planner = AssignmentPlanner(directory)
        structural, llm_ready = planner.plan_batch([flag, generic], state)
        validated = planner.validate_llm_decision(
            RouterDecision(
                assignments=[
                    WorkerAssignment(
                        todo_id=generic.todo_id, worker_name="missing-worker"
                    ),
                    WorkerAssignment(
                        todo_id="missing-todo", worker_name="artifact-worker"
                    ),
                    WorkerAssignment(
                        todo_id=generic.todo_id, worker_name="artifact-worker"
                    ),
                    WorkerAssignment(
                        todo_id=generic.todo_id, worker_name="flag-worker"
                    ),
                ]
            ),
            llm_ready,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in structural],
            [(flag.todo_id, "flag-worker")],
        )
        self.assertEqual([todo.todo_id for todo in llm_ready], [generic.todo_id])
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in validated],
            [(generic.todo_id, "artifact-worker")],
        )

    def _make_dispatch_controller(
        self,
        *,
        state: RunState,
        router,
        agent_directory: AgentDirectory,
        events: RuntimeEventController,
        execution=None,
        max_consecutive_empty_rounds: int = 1,
        assignment_budget: int = 2,
        journal: RunJournal | None = None,
        progress_threshold: int = 10,
        closure=None,
    ) -> DispatchCycleController:
        termination = RunTerminationController(state, events=events)
        if journal is None:
            journal = RunJournal(state)
        return DispatchCycleController(
            state=state,
            router=router,
            agent_directory=agent_directory,
            events=events,
            termination=termination,
            execution=execution if execution is not None else _DispatchExecution(),
            transient_llm=routed_transient_llm_handling(
                termination=termination, events=events
            ),
            closure=closure if closure is not None else _StubClosure(),
            progress=RunProgressController(
                state=state,
                events=events,
                threshold=progress_threshold,
                journal=journal,
            ),
            planner=object(),
            assignment_budget=lambda: assignment_budget,
            max_consecutive_empty_rounds=max_consecutive_empty_rounds,
            journal=journal,
        )

    def test_dispatch_cycle_handles_empty_router_decisions(self) -> None:
        state = RunState(objective="Solve.")
        events: list[tuple[str, dict[str, object]]] = []
        controller = self._make_dispatch_controller(
            state=state,
            router=_DispatchRouter(RouterDecision(rationale="none")),
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=self._runtime_events(state, events),
            max_consecutive_empty_rounds=2,
        )
        first = controller.dispatch(cycle=1, planner_summary="planned")
        self.assertTrue(first.retry_cycle)
        self.assertFalse(first.halt_run)
        self.assertEqual(controller.consecutive_empty_rounds, 1)
        second = controller.dispatch(cycle=2, planner_summary="planned")
        self.assertTrue(second.halt_run)
        self.assertEqual(state.stop_reason, "router_no_assignments")
        self.assertEqual(controller.consecutive_empty_rounds, 2)

    def test_dispatch_cycle_reconciles_unsatisfiable_dependencies(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(
            TodoItem(goal="Use missing input", depends_on=["missing"])
        )
        events: list[tuple[str, dict[str, object]]] = []
        controller = self._make_dispatch_controller(
            state=state,
            router=_DispatchRouter(RouterDecision(rationale="none")),
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=self._runtime_events(state, events),
            max_consecutive_empty_rounds=2,
        )
        result = controller.dispatch(cycle=4, planner_summary="planned")
        self.assertTrue(result.halt_run)
        self.assertEqual(todo.status.value, "blocked")
        self.assertEqual(controller.consecutive_empty_rounds, 0)
        dep_events = [
            payload
            for _, payload in events
            if payload.get("event_type") == "todo_dependency_blocked"
        ]
        self.assertEqual(len(dep_events), 1)
        self.assertEqual(dep_events[0]["todo_id"], todo.todo_id)

    def test_dispatch_cycle_emits_no_assignments_event_and_blocks_open(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Never routed."))
        events: list[tuple[str, dict[str, object]]] = []
        checkpoints: list[bool] = []
        controller = self._make_dispatch_controller(
            state=state,
            router=_DispatchRouter(RouterDecision(rationale="none")),
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=self._runtime_events(state, events, checkpoints),
            max_consecutive_empty_rounds=1,
        )
        result = controller.dispatch(cycle=9, planner_summary="planned")
        self.assertTrue(result.halt_run)
        self.assertEqual(state.stop_reason, "router_no_assignments")
        self.assertEqual(todo.status.value, "blocked")
        self.assertTrue(checkpoints)
        self.assertTrue(
            any("router selected no assignments" in message for message, _ in events)
        )

    def test_orchestrator_delegates_empty_dispatch_to_dispatch_controller(self) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        self.assertNotIn("handle_empty_decision", run_source)
        self.assertNotIn("block_open_todos", run_source)
        self.assertNotIn("_empty_dispatch_controller", run_source)

    def test_dispatch_cycle_controller_owns_route_execute_and_complete(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Run routed todo."))
        router = _DispatchRouter(
            RouterDecision(
                assignments=[
                    WorkerAssignment(todo_id=todo.todo_id, worker_name="runtime-worker")
                ]
            )
        )
        router.summarize_round = (
            lambda state, *, results: RouterRoundSummary(
                summary="; ".join(result.summary for result in results),
                direct_results=[result.summary for result in results],
            )
        )
        execution = _DispatchExecution()
        controller = self._make_dispatch_controller(
            state=state,
            router=router,
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=self._runtime_events(state),
            execution=execution,
            assignment_budget=2,
        )
        result = controller.dispatch(cycle=5, planner_summary="planned")
        self.assertFalse(result.retry_cycle)
        self.assertFalse(result.halt_run)
        self.assertEqual(router.calls, 1)
        self.assertEqual(router.max_assignments, 2)
        self.assertEqual(execution.calls, 1)
        self.assertEqual(state.rounds[0].planner_summary, "planned")

    def test_dispatch_cycle_controller_owns_empty_route_recovery(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        queue.enqueue(TodoItem(goal="Unrouted."))
        events: list[tuple[str, dict[str, object]]] = []
        controller = self._make_dispatch_controller(
            state=state,
            router=_DispatchRouter(RouterDecision(rationale="none")),
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=self._runtime_events(state, events),
            max_consecutive_empty_rounds=1,
            assignment_budget=1,
        )
        result = controller.dispatch(cycle=6, planner_summary="planned")
        self.assertTrue(result.halt_run)
        self.assertEqual(state.stop_reason, "router_no_assignments")
        self.assertTrue(
            any(("router selected no assignments" in message for message, _ in events))
        )

    def test_orchestrator_delegates_dispatch_cycle(self) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        self.assertFalse(hasattr(Orchestrator, "route"))
        self.assertNotIn("routing ready todos", run_source)
        self.assertNotIn("reset_empty_rounds", run_source)
        self.assertNotIn("_round_completion_controller.complete", run_source)
        self.assertIn("_dispatch_cycle_controller.dispatch", run_source)

    def test_deterministic_closure_policy_recognizes_generated_artifact_todos(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        state.artifacts["artifact-1"] = Artifact(
            artifact_id="artifact-1",
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script/out.png",
            source="script.exec",
        )
        todo = TodoItem(
            goal="Inspect generated image.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "artifact-followup",
                "dispatch_intent": {
                    "profile": "image_inspection",
                    "required_capability": "png.inspect",
                },
                "path": "/home/ctfplayer/ctf_files/.autopentest_artifacts/script/out.png",
            },
        )
        self.assertTrue(DeterministicClosurePolicy.has_generated_artifact(state))
        self.assertTrue(DeterministicClosurePolicy.is_final_closure_todo(todo))

    def test_core_runtime_no_longer_reads_capability_hint(self) -> None:
        import killchain_docker
        from pathlib import Path

        root = Path(killchain_docker.__file__).parent
        scanned = [
            root / "state",
            root / "orchestrator",
            root / "workers",
            root / "prompt_projection.py",
        ]
        offenders: list[str] = []
        for path in scanned:
            files = [path] if path.is_file() else path.rglob("*.py")
            for file_path in files:
                text = file_path.read_text()
                if "capability_hint" in text:
                    offenders.append(str(file_path.relative_to(root.parent)))
        self.assertEqual(offenders, [])

    def test_core_runtime_no_longer_reads_execution_closure_context_flag(self) -> None:
        import killchain_docker
        from pathlib import Path

        root = Path(killchain_docker.__file__).parent
        scanned = [
            root / "state",
            root / "orchestrator",
            root / "workers",
            root / "prompt_projection.py",
        ]
        forbidden = (
            '"execution_closure": True',
            'context["execution_closure"]',
            'context.get("execution_closure")',
        )
        offenders: list[str] = []
        for path in scanned:
            files = [path] if path.is_file() else path.rglob("*.py")
            for file_path in files:
                text = file_path.read_text()
                if any((pattern in text for pattern in forbidden)):
                    offenders.append(str(file_path.relative_to(root.parent)))
        self.assertEqual(offenders, [])

    def test_agent_directory_lifecycle_tracks_assignment(self) -> None:
        worker = _RuntimeWorker()
        directory = AgentDirectory.from_workers([worker])
        directory.lifecycle.begin(worker.name, "todo-1")
        self.assertEqual(
            directory.lifecycle.snapshot()[worker.name].status, AgentStatus.RUNNING
        )
        directory.lifecycle.finish(worker.name, success=True)
        self.assertEqual(
            directory.lifecycle.snapshot()[worker.name].status, AgentStatus.COMPLETED
        )

    def test_agent_lifecycle_owns_agent_runtime_transitions(self) -> None:
        source = inspect.getsource(AgentLifecycle)
        self.assertFalse(hasattr(AgentRuntimeState, "begin"))
        self.assertFalse(hasattr(AgentRuntimeState, "finish"))
        self.assertFalse(hasattr(AgentRuntimeState, "interrupt"))
        self.assertIn("state.status = AgentStatus.RUNNING", source)
        self.assertIn("state.status = AgentStatus.COMPLETED", source)
        self.assertIn("state.status = AgentStatus.INTERRUPTED", source)
        self.assertNotIn(".begin(todo_id)", source)
        self.assertNotIn(".finish(success=", source)
        self.assertNotIn(".interrupt(reason)", source)

    def test_assignment_lifecycle_controller_coordinates_runtime_agent_and_todo(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Run assignment."))
        worker = _RuntimeWorker()
        lifecycle = AgentLifecycle()
        registry = RuntimeTaskRegistry()
        controller = AssignmentLifecycleController(
            state=state,
            lifecycle=lifecycle,
            registry=registry,
            todos=queue,
        )
        runtime_task = controller.begin(cycle=3, todo=todo, worker=worker)
        self.assertEqual(todo.status.value, "running")
        self.assertEqual(lifecycle.snapshot()[worker.name].status, AgentStatus.RUNNING)
        self.assertEqual(runtime_task.status, RuntimeTaskStatus.RUNNING)
        controller.transient_interrupt(
            todo=todo,
            worker=worker,
            runtime_task=runtime_task,
            reason="temporary LLM outage",
        )
        self.assertEqual(todo.status.value, "pending")
        self.assertEqual(
            lifecycle.snapshot()[worker.name].status, AgentStatus.INTERRUPTED
        )
        self.assertEqual(runtime_task.status, RuntimeTaskStatus.INTERRUPTED)

    def test_runtime_task_registry_owns_runtime_task_lifecycle(self) -> None:
        source = inspect.getsource(AssignmentLifecycleController)
        self.assertFalse(hasattr(RuntimeTaskState, "start"))
        self.assertFalse(hasattr(RuntimeTaskState, "complete"))
        self.assertFalse(hasattr(RuntimeTaskState, "fail"))
        self.assertFalse(hasattr(RuntimeTaskState, "interrupt"))
        self.assertIn("self.registry.start", source)
        self.assertIn("self.registry.complete", source)
        self.assertIn("self.registry.fail", source)
        self.assertIn("self.registry.interrupt", source)
        self.assertNotIn("runtime_task.start", source)
        self.assertNotIn("runtime_task.complete", source)
        self.assertNotIn("runtime_task.fail", source)
        self.assertNotIn("runtime_task.interrupt", source)

    def test_assignment_execution_uses_assignment_lifecycle_controller(self) -> None:
        source = inspect.getsource(Execution.run)
        self.assertIn("self.assignment_lifecycle.begin", source)
        self.assertIn("self.assignment_lifecycle.complete", source)
        self.assertIn("self.assignment_lifecycle.fail", source)
        self.assertIn("self.assignment_lifecycle.interrupt", source)
        self.assertNotIn("RuntimeTaskState(", source)
        self.assertNotIn("self.registry.register", source)
        self.assertNotIn("self.lifecycle.begin", source)
        self.assertNotIn("self.lifecycle.finish", source)
        self.assertNotIn("runtime_task.start()", source)
        self.assertNotIn("runtime_task.complete", source)
        self.assertNotIn("runtime_task.fail", source)
        self.assertNotIn("runtime_task.interrupt", source)

    def test_script_plugin_delegates_runtime_and_output_logic(self) -> None:
        script_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/script.py"
        ).read_text()
        runtime_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/script_runtime.py"
        ).read_text()
        output_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/script_output.py"
        ).read_text()
        self.assertIn("python_runtime_guard_wrapper", script_source)
        self.assertIn("script_failure_signal", script_source)
        self.assertIn("flag_candidates_from_script_stdout", script_source)
        self.assertNotIn("def _python_runtime_guard_wrapper", script_source)
        self.assertNotIn("def _script_failure_signal", script_source)
        self.assertNotIn("def _readable_near_misses", script_source)
        self.assertNotIn("def _flag_candidates_from_script_stdout", script_source)
        self.assertNotIn("_NETWORK_SCRIPT_RE", script_source)
        self.assertNotIn("_DIAGNOSTIC_LINE_RE", script_source)
        self.assertNotIn("_PYTHON_RANGE_LIMIT", script_source)
        self.assertIn("def python_runtime_guard_wrapper", runtime_source)
        self.assertIn("def effective_timeout_s", runtime_source)
        self.assertIn("def script_uses_network_io", runtime_source)
        self.assertIn("def script_failure_signal", output_source)
        self.assertIn("def readable_near_misses", output_source)
        self.assertIn("def flag_candidates_from_script_stdout", output_source)

    def test_shell_plugin_delegates_guard_and_output_logic(self) -> None:
        shell_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/shell.py"
        ).read_text()
        guard_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/shell_guard.py"
        ).read_text()
        output_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/shell_output.py"
        ).read_text()
        self.assertIn("class ShellPlugin", shell_source)
        self.assertIn("protected_shell_command", shell_source)
        self.assertIn("normalize_shell_stderr_diagnostics", shell_source)
        self.assertNotIn("def build_output", shell_source)
        self.assertNotIn("def package_install_block_reason", shell_source)
        self.assertNotIn("def normalize_shell_stderr_diagnostics", shell_source)
        self.assertNotIn("_PACKAGE_MANAGER_RE", shell_source)
        self.assertNotIn("_MASKED_COMMAND_ERROR_RE", shell_source)
        self.assertNotIn("artifact_records_from_stdout", shell_source)
        self.assertIn("def package_install_block_reason", guard_source)
        self.assertIn("def normalize_shell_stderr_diagnostics", guard_source)
        self.assertIn("def unbounded_extraction_block_reason", guard_source)
        self.assertIn("def build_output", output_source)
        self.assertIn("def shell_failure_signal", output_source)
        self.assertIn("def masked_command_error_detail", output_source)

    def test_old_core_helper_reexports_and_llm_model_alias_are_removed(self) -> None:
        base_source = (
            PROJECT_ROOT / "killchain_docker/tools/plugins/_base.py"
        ).read_text()
        gateway_source = (PROJECT_ROOT / "killchain_docker/llm/gateway.py").read_text()
        self.assertNotIn("_truncate", base_source)
        self.assertNotIn('alias="model"', gateway_source)
        self.assertNotIn('payload.get("model")', gateway_source)
        self.assertNotIn("model=default_model", gateway_source)

    def test_batch_docker_requires_posix_locking_without_windows_fallback(self) -> None:
        source = (PROJECT_ROOT / "killchain_docker/batch/docker.py").read_text()
        self.assertIn("import fcntl", source)
        self.assertNotIn("except ImportError", source)
        self.assertNotIn("Windows compatibility", source)
        self.assertNotIn("fcntl is None", source)

    def test_execution_controller_converts_unhandled_exception_to_result(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Fail safely."))
        worker = _RuntimeWorker(fail=True)
        lifecycle = AgentLifecycle()
        registry = RuntimeTaskRegistry()
        events: list[tuple[str, dict[str, object]]] = []
        controller = Execution(
            state=state,
            lifecycle=lifecycle,
            registry=registry,
            events=self._runtime_events(state, events),
        )
        result = controller.run(cycle=1, todo=todo, worker=worker)
        self.assertFalse(result.success)
        self.assertIn("RuntimeError", result.summary)
        self.assertEqual(lifecycle.snapshot()[worker.name].status, AgentStatus.FAILED)
        task = next(iter(registry.snapshot().values()))
        self.assertEqual(task.status, RuntimeTaskStatus.FAILED)
        self.assertTrue(is_terminal_runtime_task_status(task.status))
        self.assertTrue(
            any(("UNHANDLED EXCEPTION" in message for message, _ in events))
        )

    def test_closure_controller_uses_event_controller_not_raw_callbacks(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        events = self._runtime_events(state)
        execution = Execution(
            state=state,
            lifecycle=AgentLifecycle(),
            registry=RuntimeTaskRegistry(),
            events=events,
        )
        directory = AgentDirectory.from_workers([_RuntimeWorker()])
        closure = ClosureExecutionController(
            state=state,
            todos=_todo_queue(state),
            agent_directory=directory,
            execution=execution,
            events=events,
        )
        self.assertIs(closure.events, events)
        self.assertFalse(hasattr(closure, "checkpoint"))
        self.assertFalse(hasattr(closure, "sync_background_flags"))
        self.assertFalse(hasattr(closure, "emit"))

    def test_dispatch_cycle_records_round_summary_and_progress(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Run."))
        events: list[tuple[str, dict[str, object]]] = []
        checkpoints: list[bool] = []
        event_controller = self._runtime_events(state, events, checkpoints)
        router = _SummaryRouter()
        router.assignments = [
            WorkerAssignment(todo_id=todo.todo_id, worker_name="runtime-worker")
        ]
        journal = RunJournal(state)
        controller = self._make_dispatch_controller(
            state=state,
            router=router,
            agent_directory=AgentDirectory.from_workers([_RuntimeWorker()]),
            events=event_controller,
            max_consecutive_empty_rounds=1,
            assignment_budget=1,
            journal=journal,
            progress_threshold=1,
            closure=_StubClosure(),
        )
        result = controller.dispatch(cycle=7, planner_summary="planned")
        self.assertFalse(result.retry_cycle)
        self.assertFalse(result.halt_run)
        self.assertEqual(router.calls, 1)
        self.assertEqual(state.rounds[0].planner_summary, "planned")
        self.assertEqual(state.rounds[0].summary.summary, "cycle 7 executed")
        self.assertEqual(
            state.rounds[0].assignments[0].worker_name, "runtime-worker"
        )
        self.assertEqual(state.metadata["forced_pivot"]["pivot_number"], 1)
        self.assertTrue(any(("router summary" in message for message, _ in events)))
        self.assertTrue(checkpoints)

    def test_execution_controller_applies_result_and_emits_runtime_event(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Run."))
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="runtime-worker",
            success=True,
            summary="done",
            output_context={"stdout": "done"},
            memory_updates={"format": "png"},
        )
        events: list[tuple[str, dict[str, object]]] = []
        controller = Execution(
            state=state,
            lifecycle=AgentLifecycle(),
            registry=RuntimeTaskRegistry(),
            events=self._runtime_events(state, events),
        )
        controller.apply_result(cycle=7, todo=todo, result=result)
        self.assertEqual(todo.status.value, "completed")
        self.assertEqual(state.run_memory["format"], "png")
        self.assertEqual(events[-1][1]["event_type"], "worker_result")

    def test_runtime_event_controller_owns_worker_progress_context(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(
            TodoItem(goal="Report progress.", phase=TodoPhase.RECON)
        )
        _todo_queue(state).start(todo, "runtime-worker")
        events: list[tuple[str, dict[str, object]]] = []
        checkpoints: list[bool] = []
        controller = self._runtime_events(state, events, checkpoints)
        controller.worker_progress(4, state, todo, "halfway")
        self.assertEqual(events[0][1]["event_type"], "worker_progress")
        self.assertEqual(events[0][1]["todo_id"], todo.todo_id)
        self.assertEqual(events[0][1]["todo_status"], "running")
        self.assertEqual(events[0][1]["worker"], "runtime-worker")
        self.assertTrue(checkpoints)

    def test_background_flag_validation_controller_solves_from_candidates(self) -> None:
        state = RunState(objective="Solve.")
        checkpointed: list[bool] = []
        controller = BackgroundFlagValidationController(
            state=state,
            workers=[_ExpectedFlagWorker()],
            emit=lambda _message: None,
            checkpoint=lambda: checkpointed.append(True),
        )
        controller.start()
        try:
            queued = controller.enqueue_candidates(
                [
                    FlagCandidate(value="flag{miss}", confidence=0.5),
                    FlagCandidate(value="flag{ok}", confidence=1.0),
                ]
            )
            solved = controller.sync(3, wait_s=0.5)
        finally:
            controller.stop()
        self.assertEqual(queued, 2)
        self.assertTrue(solved)
        self.assertTrue(state.solved)
        self.assertEqual(state.validated_flag, "flag{ok}")
        self.assertTrue(checkpointed)

    def test_run_termination_controller_records_llm_error_and_blocks_open_todos(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        running = _todo_queue(state).enqueue(TodoItem(goal="Running."))
        _todo_queue(state).start(running, "runtime-worker")
        pending = _todo_queue(state).enqueue(
            TodoItem(goal="Pending.", dedupe_key="pending")
        )
        controller = RunTerminationController(state, llm_error_message_limit=12)
        controller.mark_llm_error(
            5,
            "planner",
            LLMClientError(
                "x" * 30,
                kind="schema_validation",
                schema_name="Plan",
                model="test-model",
                attempts=2,
            ),
        )
        self.assertEqual(state.status.value, "failed")
        self.assertEqual(state.stop_reason, "llm_error")
        self.assertEqual(running.status.value, "failed")
        self.assertEqual(pending.status.value, "blocked")
        self.assertEqual(state.metadata["last_llm_error"]["cycle"], 5)
        self.assertEqual(state.metadata["last_llm_error"]["schema_name"], "Plan")
        self.assertIn("[truncated]", state.metadata["last_llm_error"]["message"])
        self.assertFalse(hasattr(RunTerminationController, "block_open_todos"))

    def test_run_termination_controller_owns_transient_skip_budget(self) -> None:
        state = RunState(objective="Solve.")
        events: list[str] = []
        controller = RunTerminationController(
            state,
            events=RuntimeEventController(
                state=state,
                emit=lambda message, **_kwargs: events.append(message),
                checkpoint=lambda: None,
            ),
            max_transient_skips=1,
        )
        transient = LLMClientError("temporary", transient=True)
        first = controller.skip_transient_llm_error(2, "planner", transient)
        second = controller.skip_transient_llm_error(3, "planner", transient)
        permanent = controller.skip_transient_llm_error(
            4, "planner", LLMClientError("schema", transient=False)
        )
        self.assertTrue(first)
        self.assertFalse(second)
        self.assertFalse(permanent)
        self.assertEqual(controller.transient_skip_count, 1)
        self.assertIn("skip 1/1", events[0])
        self.assertIn("transient LLM error skipped", state.orchestration_notes[0])

    def test_transient_skip_counter_resets_on_successful_step(self) -> None:
        """A successful cycle clears the consecutive transient-skip budget.

        Without the reset, an upstream provider blip in cycle 2 + another in
        cycle 4 would accumulate even if cycle 3 made progress, silently
        dooming the run.
        """

        state = RunState(objective="Solve.")
        controller = RunTerminationController(state, max_transient_skips=2)
        transient = LLMClientError("temporary", transient=True)
        controller.skip_transient_llm_error(1, "planner", transient)
        controller.skip_transient_llm_error(2, "planner", transient)
        self.assertEqual(controller.transient_skip_count, 2)
        controller.note_successful_step()
        self.assertEqual(controller.transient_skip_count, 0)
        # After reset, two more transient skips are tolerated again.
        self.assertTrue(controller.skip_transient_llm_error(3, "planner", transient))
        self.assertTrue(controller.skip_transient_llm_error(4, "planner", transient))

    def test_skip_budget_is_per_source(self) -> None:
        """Cross-source successes do not shield against same-source failure.

        A planner skip plus repeated worker skips should still halt at the
        worker's own per-source budget — not at the sum across sources.  And
        a planner success should clear only the planner slot, leaving any
        in-flight worker streak intact.
        """

        state = RunState(objective="Solve.")
        controller = RunTerminationController(state, max_transient_skips=2)
        transient = LLMClientError("temporary", transient=True)
        # Planner blips once, then recovers — its slot clears.
        self.assertTrue(controller.skip_transient_llm_error(1, "planner", transient))
        controller.note_successful_step("planner")
        # Worker now keeps failing; budget is its own.
        self.assertTrue(controller.skip_transient_llm_error(2, "worker", transient))
        self.assertTrue(controller.skip_transient_llm_error(3, "worker", transient))
        # Third worker skip exhausts the worker budget regardless of planner state.
        self.assertFalse(controller.skip_transient_llm_error(4, "worker", transient))
        # Planner resetting does not reset the worker counter.
        controller.note_successful_step("planner")
        self.assertFalse(controller.skip_transient_llm_error(5, "worker", transient))
        # Worker recovering then failing again starts a fresh worker streak.
        controller.note_successful_step("worker")
        self.assertTrue(controller.skip_transient_llm_error(6, "worker", transient))

    def test_run_termination_controller_owns_step_llm_failure_policy(self) -> None:
        transient_state = RunState(objective="Solve.")
        transient_checkpoints: list[bool] = []
        transient = RunTerminationController(
            transient_state,
            events=self._runtime_events(
                transient_state, checkpoints=transient_checkpoints
            ),
            max_transient_skips=1,
        )
        skipped = transient.handle_step_llm_error(
            cycle=2,
            source="planner",
            exc=LLMClientError("temporary", transient=True),
            permanent_message="planner failed",
        )
        halted = transient.handle_step_llm_error(
            cycle=3,
            source="planner",
            exc=LLMClientError("temporary again", transient=True),
            permanent_message="planner failed",
        )
        failed_state = RunState(objective="Solve.")
        failed_checkpoints: list[bool] = []
        failed = RunTerminationController(
            failed_state,
            events=self._runtime_events(failed_state, [], failed_checkpoints),
        )
        raised = failed.handle_step_llm_error(
            cycle=4,
            source="router",
            exc=LLMClientError("schema"),
            permanent_message="router failed",
        )
        self.assertEqual(skipped, LLMFailureAction.RETRY_CYCLE)
        self.assertEqual(halted, LLMFailureAction.HALT_RUN)
        self.assertEqual(transient_state.stop_reason, "llm_transient_error")
        self.assertEqual(raised, LLMFailureAction.RAISE)
        self.assertEqual(failed_state.stop_reason, "llm_error")
        self.assertEqual(len(transient_checkpoints), 2)
        self.assertEqual(len(failed_checkpoints), 1)
        self.assertFalse(hasattr(Orchestrator, "_handle_step_llm_error"))
        self.assertFalse(hasattr(RunTerminationController, "terminal_unsolved_reason"))

    def test_handle_step_llm_error_skips_schema_validation_within_budget(self) -> None:
        state = RunState(objective="Solve.")
        events: list[str] = []
        checkpoints: list[bool] = []
        controller = RunTerminationController(
            state,
            events=self._runtime_events(state, events, checkpoints),
            max_transient_skips=1,
        )
        first = controller.handle_step_llm_error(
            cycle=2,
            source="planner",
            exc=LLMClientError(
                "PlannerDecision validation failed",
                kind="schema_validation",
                schema_name="PlannerDecision",
            ),
            permanent_message="planner permanently failed",
        )
        second = controller.handle_step_llm_error(
            cycle=3,
            source="planner",
            exc=LLMClientError(
                "PlannerDecision validation failed again",
                kind="schema_validation",
                schema_name="PlannerDecision",
            ),
            permanent_message="planner permanently failed",
        )
        self.assertEqual(first, LLMFailureAction.RETRY_CYCLE)
        self.assertEqual(second, LLMFailureAction.HALT_RUN)
        self.assertEqual(state.stop_reason, "llm_transient_error")
        self.assertEqual(len(checkpoints), 2)
        self.assertTrue(
            any("schema-validation LLM error" in event[0] for event in events),
            events,
        )

    def test_run_termination_controller_finalizes_terminal_outcomes(self) -> None:
        state = RunState(objective="Solve.")
        queue = _todo_queue(state)
        todo = queue.enqueue(TodoItem(goal="Partial."))
        queue.partial(todo, "some evidence")
        controller = RunTerminationController(state)
        controller.finalize(max_cycles_exhausted=False)
        self.assertEqual(state.status.value, "failed")
        self.assertEqual(state.stop_reason, "partial_todos_unsolved")

    def test_orchestrator_owns_start_stop_interrupt_and_runtime_llm_error(
        self,
    ) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        self.assertIn("self._outcome.start", run_source)
        self.assertIn("self._background_flags.start()", run_source)
        self.assertIn("self._background_flags.stop()", run_source)
        self.assertIn("self._handle_interrupt", run_source)
        self.assertIn("self._handle_uncaught_llm_error", run_source)
        interrupt_source = inspect.getsource(Orchestrator._handle_interrupt)
        self.assertIn("interrupt_running", interrupt_source)
        self.assertIn("[interrupt]", interrupt_source)
        llm_error_source = inspect.getsource(Orchestrator._handle_uncaught_llm_error)
        self.assertIn("mark_llm_error", llm_error_source)
        self.assertIn("LLM error - aborting run", llm_error_source)

    def test_orchestrator_delegates_run_lifecycle(self) -> None:
        run_source = inspect.getsource(Orchestrator.run)
        self.assertNotIn("state.status = RunStatus.RUNNING", run_source)
        self.assertNotIn("run interrupted by", run_source)
        self.assertNotIn("marked running todos as interrupted", run_source)
        self.assertIn("self._begin_cycle", run_source)
        self.assertIn("self._finalize", run_source)

    def test_orchestrator_owns_post_loop_closure_and_terminal_status(
        self,
    ) -> None:
        finalize_source = inspect.getsource(Orchestrator._finalize)
        self.assertIn("final_deterministic_evidence_pass", finalize_source)
        self.assertIn("final_flag_validation_pass", finalize_source)
        self.assertIn("self._termination_controller.finalize", finalize_source)
        self.assertTrue(
            hasattr(Orchestrator, "FINAL_DETERMINISTIC_CLOSURE_PASSES")
        )
        self.assertTrue(
            hasattr(Orchestrator, "FINAL_DETERMINISTIC_CLOSURE_ASSIGNMENTS")
        )

    def test_run_termination_controller_interrupts_transient_llm_exhaustion(
        self,
    ) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Retry."))
        _todo_queue(state).start(todo, "runtime-worker")
        events: list[tuple[str, dict[str, object]]] = []
        controller = RunTerminationController(
            state, events=self._runtime_events(state, events)
        )
        controller.halt_after_transient_llm_error(
            3,
            "runtime-worker",
            LLMClientError("temporarily unavailable", transient=True),
            todo=todo,
        )
        self.assertEqual(state.status.value, "failed")
        self.assertEqual(state.stop_reason, "llm_transient_error")
        self.assertEqual(todo.status.value, "interrupted")
        self.assertIn("llm_error:runtime-worker", todo.error or "")
        self.assertEqual(events[0][1]["event_type"], "llm_transient_error")

    def test_run_journal_owns_append_only_state_logs(self) -> None:
        state = RunState(objective="Solve.")
        journal = RunJournal(state)
        journal.orchestration_notes([" first ", "", "second"])
        first = journal.rejected_flag_candidate(
            value="flag{bad}", reason="candidate mismatch", evidence_refs=["evidence-1"]
        )
        second = journal.rejected_flag_candidate(
            value="flag{bad}", reason="candidate mismatch", evidence_refs=["evidence-2"]
        )
        result = WorkerResult(
            todo_id="todo-1",
            worker_name="runtime-worker",
            success=True,
            summary="done",
            notes=["worker note"],
        )
        journal.worker_execution(result)
        journal.notes(result.notes)
        self.assertEqual(state.orchestration_notes, ["first", "second"])
        self.assertIs(first, second)
        self.assertEqual(
            state.rejected_flag_candidates[0].evidence_refs,
            ["evidence-1", "evidence-2"],
        )
        self.assertEqual(state.execution_log[0].task_id, "todo-1")
        self.assertEqual(state.notes, ["worker note"])

    def test_worker_result_applier_owns_worker_result_application(self) -> None:
        state = RunState(objective="Solve.")
        todo = _todo_queue(state).enqueue(TodoItem(goal="Capture grounded facts."))
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="runtime-worker",
            success=True,
            summary="done",
            memory_updates={"format": "zip archive"},
        )
        WorkerResultApplier(state).apply(result)
        self.assertFalse(hasattr(RunState, "apply_worker_result"))
        self.assertFalse(hasattr(RunState, "apply_state_delta"))
        self.assertFalse(hasattr(RunState, "record_round"))
        self.assertFalse(hasattr(RunState, "active_flag_candidates"))
        self.assertFalse(hasattr(WorkerResultApplier, "active_flag_candidates"))
        self.assertIsNone(
            importlib.util.find_spec("killchain_docker.state.transitions")
        )
        self.assertFalse(hasattr(RunState, "todo_family_counts"))
        self.assertEqual(todo.status.value, "completed")
        self.assertEqual(state.run_memory["format"], "zip archive")
        self.assertEqual(state.execution_log[0].worker_name, "runtime-worker")

    def test_tool_specs_expose_execution_policy(self) -> None:
        artifact = tool_spec(ToolCapability.ARTIFACT_TRIAGE)
        shell = tool_spec(ToolCapability.SHELL_EXEC)
        strings = tool_spec(ToolCapability.STRINGS_CMD)
        self.assertIsNotNone(artifact)
        self.assertTrue(artifact.execution_policy().read_only)
        self.assertTrue(artifact.execution_policy().concurrency_safe)
        self.assertIsNotNone(shell)
        self.assertTrue(shell.execution_policy().destructive)
        self.assertEqual(
            shell.execution_policy().interrupt_behavior, ToolInterruptBehavior.CANCEL
        )
        self.assertIsNotNone(strings)
        self.assertTrue(strings.execution_policy().read_only)
        self.assertTrue(strings.execution_policy().concurrency_safe)

    def test_routed_execution_batches_concurrency_safe_assignments(self) -> None:
        execution_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/execution.py"
        ).read_text()
        dispatch_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/dispatch/controller.py"
        ).read_text()
        batch_source = (
            PROJECT_ROOT / "killchain_docker/orchestrator/dispatch/batches.py"
        ).read_text()
        self.assertIn("assignment_execution_batches(", dispatch_source)
        self.assertIn("ThreadPoolExecutor", execution_source)
        self.assertIn("as_completed", execution_source)
        self.assertIn("tool_spec(", batch_source)
        self.assertIn("spec.direct", batch_source)
        self.assertIn("spec.read_only", batch_source)
        self.assertIn("spec.concurrency_safe", batch_source)
        self.assertIn("not spec.destructive", batch_source)


if __name__ == "__main__":
    unittest.main()
