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


if __name__ == "__main__":
    unittest.main()
