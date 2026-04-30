"""Tests for the split planner pipeline."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.llm import StaticLLMClient
from nyuctf_mutil_killchain.orchestrator.planning import (
    BootstrapSeeder,
    LLMPlanner,
    PlannedTask,
    PlannerDecision,
    TaskDeduper,
    TaskNormalizer,
)
from nyuctf_mutil_killchain.state import GlobalState


def _state_with(files: list[str], scope: list[str] | None = None) -> GlobalState:
    return GlobalState(
        objective="Solve test challenge.",
        authorized_scope=list(scope or []),
        metadata={
            "challenge": {
                "name": "test",
                "category": "crypto",
                "flag_format": "flag{...}",
                "files": files,
                "server_name": "",
                "port": None,
            }
        },
    )


class BootstrapSeederTests(unittest.TestCase):
    def test_seed_artifact_triage_when_files_present(self):
        state = _state_with(["a.py", "b"])
        decision = BootstrapSeeder().plan(state)
        types = [t.task_type for t in decision.tasks]
        self.assertIn("artifact.triage", types)

    def test_seed_recon_for_each_scope(self):
        state = _state_with([], scope=["http://x:80", "tcp://y:9000"])
        decision = BootstrapSeeder().plan(state)
        scopes = [
            t.input_context["scope"]
            for t in decision.tasks
            if t.task_type == "recon.enumerate_scope"
        ]
        self.assertEqual(scopes, ["http://x:80", "tcp://y:9000"])

    def test_no_seed_when_already_present(self):
        state = _state_with(["a.py"])
        BootstrapSeeder().plan(state)  # no-op until we queue
        for task in BootstrapSeeder().plan(state).tasks:
            state.queue_task(task.to_task())
        # Re-plan should not produce duplicate seeds
        again = BootstrapSeeder().plan(state)
        self.assertEqual([t.task_type for t in again.tasks], [])

    def test_note_when_no_scope_no_files(self):
        state = _state_with([], scope=[])
        decision = BootstrapSeeder().plan(state)
        self.assertTrue(any("No authorized scope" in note for note in decision.notes))


class TaskNormalizerTests(unittest.TestCase):
    def test_fills_files_root_for_artifact_tasks(self):
        state = _state_with(["solve.py"])
        task = PlannedTask(
            title="x", description="y",
            task_type="artifact.source_review",
            input_context={"source_files": ["solve.py"]},
        )
        TaskNormalizer().fill(task, state)
        self.assertEqual(task.input_context["files_root"], "/home/ctfplayer/ctf_files")

    def test_infers_source_files_when_missing(self):
        state = _state_with(["solve.py", "data.bin"])
        task = PlannedTask(
            title="x", description="y",
            task_type="artifact.source_review",
            input_context={},
        )
        TaskNormalizer().fill(task, state)
        self.assertEqual(task.input_context["source_files"], ["solve.py"])

    def test_infers_binary_files_for_binary_triage(self):
        state = _state_with(["data.bin", "stfu", "x.py"])
        task = PlannedTask(
            title="x", description="y",
            task_type="artifact.binary_triage",
            input_context={},
        )
        TaskNormalizer().fill(task, state)
        self.assertEqual(
            sorted(task.input_context["binary_files"]),
            sorted(["data.bin", "stfu"]),
        )

    def test_overwrites_bad_files_root_value(self):
        # NYU CTF agent containers expose challenge files at one fixed path; if
        # the LLM hallucinates ``/challenge`` the worker hits ENOENT.  The
        # normalizer must force the canonical value.
        state = _state_with(["challenge.bin"])
        task = PlannedTask(
            title="solve",
            description="run script",
            task_type="solve.generate_script",
            input_context={"files_root": "/challenge"},
        )
        TaskNormalizer().fill(task, state)
        self.assertEqual(task.input_context["files_root"], "/home/ctfplayer/ctf_files")


class TaskDeduperTests(unittest.TestCase):
    def test_assigns_default_dedupe_keys(self):
        deduper = TaskDeduper()
        tasks = [
            PlannedTask(title="x", description="d", task_type="artifact.binary_triage",
                        input_context={"binary_files": ["a.bin"]}),
        ]
        merged = deduper.merge(tasks, _state_with([]))
        self.assertEqual(merged[0].dedupe_key, "artifact-binary-triage:a.bin")

    def test_drops_duplicates(self):
        deduper = TaskDeduper()
        existing = {"artifact-triage:challenge-files"}
        tasks = [
            PlannedTask(title="t1", description="d", task_type="artifact.triage",
                        input_context={}),
        ]
        merged = deduper.merge(tasks, _state_with([]), existing_keys=existing)
        self.assertEqual(merged, [])


class LLMPlannerPipelineTests(unittest.TestCase):
    def test_planner_combines_bootstrap_and_llm(self):
        state = _state_with(["solve.py"])
        llm_response = {
            "summary": "consider source review",
            "tasks": [
                {
                    "title": "Review source",
                    "description": "static review",
                    "task_type": "artifact.source_review",
                    "priority": 80,
                    "input_context": {"source_files": ["solve.py"]},
                }
            ],
            "notes": [],
            "stop_run": False,
        }
        client = StaticLLMClient([llm_response])
        planner = LLMPlanner(client)

        decision = planner.plan(state)
        types = [t.task_type for t in decision.tasks]
        self.assertIn("artifact.triage", types)
        self.assertIn("artifact.source_review", types)
        for task in decision.tasks:
            if task.task_type == "artifact.source_review":
                self.assertEqual(
                    task.input_context["files_root"], "/home/ctfplayer/ctf_files"
                )

    def test_planner_respects_llm_stop_run(self):
        state = _state_with([])
        llm_response = {"summary": "no more work", "tasks": [], "notes": [], "stop_run": True}
        planner = LLMPlanner(StaticLLMClient([llm_response]))
        decision = planner.plan(state)
        self.assertTrue(decision.stop_run)

    def test_user_prompt_exposes_blocked_task_reason(self):
        """Planner snapshot must surface ``last_error``/``error_code`` so the LLM
        can route around blocked tasks instead of re-issuing them."""

        import json
        from nyuctf_mutil_killchain.orchestrator.planning import PlanStrategy
        from nyuctf_mutil_killchain.state import Task, TaskErrorCode

        state = _state_with(["x.bin"])
        bad_task = Task(
            title="probe",
            description="probe asset",
            task_type="web.review_surface",
            input_context={"asset_id": "http://example.com:80"},
        )
        bad_task.mark_blocked(
            "asset_id 'http://example.com:80' not found in state.assets",
            error_code=TaskErrorCode.UNKNOWN_ASSET_ID,
        )
        state.queue_task(bad_task)

        strategy = PlanStrategy(StaticLLMClient([
            {"summary": "noop", "tasks": [], "notes": [], "stop_run": False}
        ]))
        snapshot = json.loads(strategy._user_prompt(state))
        history_for_task = next(
            entry for entry in snapshot["task_history"]
            if entry["task_id"] == bad_task.task_id
        )
        self.assertIn("not found in state.assets", history_for_task["last_error"])
        self.assertEqual(history_for_task["error_code"], "unknown_asset_id")

    def test_planner_accepts_string_priority(self):
        state = _state_with(["solve.py"])
        llm_response = {
            "summary": "consider source review",
            "tasks": [
                {
                    "title": "Review source",
                    "description": "static review",
                    "task_type": "artifact.source_review",
                    "priority": "high",
                    "input_context": {"source_files": ["solve.py"]},
                }
            ],
            "notes": [],
            "stop_run": False,
        }
        decision = LLMPlanner(StaticLLMClient([llm_response])).plan(state)
        sr = next(t for t in decision.tasks if t.task_type == "artifact.source_review")
        self.assertEqual(sr.priority, 75)


class PlannedTaskPriorityCoercionTests(unittest.TestCase):
    def test_string_high_is_int_75(self):
        task = PlannedTask(
            title="t", description="d",
            task_type="solve.generate_script",
            priority="high",
        )
        self.assertEqual(task.priority, 75)

    def test_string_numeric_is_parsed(self):
        task = PlannedTask(
            title="t", description="d",
            task_type="solve.generate_script",
            priority="60",
        )
        self.assertEqual(task.priority, 60)


class ConfidenceCoercionTests(unittest.TestCase):
    def test_solver_guidance_accepts_string_confidence(self):
        from nyuctf_mutil_killchain.agents.reasoning.schemas import SolverCodeGuidance

        guidance = SolverCodeGuidance(
            summary="x",
            solver_code="print(1)",
            confidence="high",
        )
        self.assertEqual(guidance.confidence, 0.75)

    def test_router_decision_accepts_string_confidence(self):
        from nyuctf_mutil_killchain.orchestrator.router import WorkerRouteDecision

        decision = WorkerRouteDecision(worker_name="w", confidence="medium")
        self.assertEqual(decision.confidence, 0.5)

    def test_flag_validation_accepts_string_confidence(self):
        from nyuctf_mutil_killchain.agents.flag import FlagValidationAssessment

        assessment = FlagValidationAssessment(summary="ok", confidence="low")
        self.assertEqual(assessment.confidence, 0.25)


if __name__ == "__main__":
    unittest.main()
