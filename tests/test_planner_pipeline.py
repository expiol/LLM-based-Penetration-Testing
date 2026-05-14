"""Tests for the high-level planner pipeline."""

from __future__ import annotations

import unittest

from killchain_docker.llm import StaticLLMClient
from killchain_docker.orchestrator.planning import (
    BootstrapSeeder,
    LLMPlanner,
    PlannedTodo,
    PlannerDecision,
    TodoDeduper,
    TodoNormalizer,
)
from killchain_docker.state import RunState


def _state(files: list[str] | None = None, scope: list[str] | None = None) -> RunState:
    return RunState(
        objective="Solve test challenge.",
        authorized_scope=list(scope or []),
        metadata={
            "challenge": {
                "name": "test",
                "category": "crypto",
                "flag_format": "flag{...}",
                "files": list(files or []),
            }
        },
    )


class BootstrapSeederTests(unittest.TestCase):
    def test_seed_artifacts_and_scope_as_high_level_todos(self) -> None:
        state = _state(["solve.py"], ["http://example.test"])
        decision = BootstrapSeeder().plan(state)
        goals = [todo.goal for todo in decision.todos]

        self.assertTrue(any("Inventory" in goal for goal in goals))
        self.assertTrue(any("Map authorized scope" in goal for goal in goals))
        self.assertTrue(all(not hasattr(todo, "task_type") for todo in decision.todos))


class TodoNormalizerTests(unittest.TestCase):
    def test_file_goal_gets_canonical_files_context(self) -> None:
        state = _state(["solve.py"])
        todo = PlannedTodo(goal="Review source files for crypto weakness.")
        TodoNormalizer().fill(todo, state)

        self.assertEqual(todo.context["files_root"], "/home/ctfplayer/ctf_files")
        self.assertEqual(todo.context["challenge_files"], ["solve.py"])


class TodoDeduperTests(unittest.TestCase):
    def test_drops_duplicate_dedupe_keys(self) -> None:
        state = _state([])
        todos = [
            PlannedTodo(goal="A", dedupe_key="same"),
            PlannedTodo(goal="B", dedupe_key="same"),
        ]
        merged = TodoDeduper().merge(todos, state)

        self.assertEqual([todo.goal for todo in merged], ["A"])


class LLMPlannerTests(unittest.TestCase):
    def test_planner_combines_bootstrap_and_llm_todos(self) -> None:
        state = _state(["solve.py"])
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "review source",
                    "todos": [
                        {
                            "goal": "Review source for weak crypto.",
                            "priority": "high",
                            "context": {"source_files": ["solve.py"]},
                            "success_criteria": ["Find the algorithm."],
                            "constraints": ["Use local files only."],
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.summary, "review source")
        self.assertGreaterEqual(len(decision.todos), 2)
        llm_todo = next(todo for todo in decision.todos if "weak crypto" in todo.goal)
        self.assertEqual(llm_todo.priority, 75)
        self.assertEqual(llm_todo.context["files_root"], "/home/ctfplayer/ctf_files")

    def test_planner_respects_stop_run(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient([
                {"summary": "done", "todos": [], "notes": [], "stop_run": True}
            ])
        )
        self.assertTrue(planner.plan(_state([])).stop_run)

    def test_planner_keeps_bootstrap_todos_when_llm_fails(self) -> None:
        planner = LLMPlanner(StaticLLMClient([]))

        decision = planner.plan(_state(["solve.py"]))

        self.assertGreaterEqual(len(decision.todos), 1)
        self.assertTrue(any("Inventory" in todo.goal for todo in decision.todos))
        self.assertTrue(any("Planner LLM failed" in note for note in decision.notes))


class PlannedTodoPriorityTests(unittest.TestCase):
    def test_string_priority_is_coerced(self) -> None:
        self.assertEqual(PlannedTodo(goal="x", priority="high").priority, 75)
        self.assertEqual(PlannedTodo(goal="x", priority="60").priority, 60)


if __name__ == "__main__":
    unittest.main()
