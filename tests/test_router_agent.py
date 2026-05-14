"""Tests for RouterAgent assignment and summary behavior."""

from __future__ import annotations

import json
import unittest

from killchain_docker.llm import StaticLLMClient
from killchain_docker.orchestrator.router import RouterAgent
from killchain_docker.state import RunState, TodoItem, TodoPhase, WorkerResult


class RouterAgentTests(unittest.TestCase):
    def test_routes_multiple_todos_to_different_workers(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        first = state.queue_todo(TodoItem(goal="Map scope", priority=90))
        second = state.queue_todo(TodoItem(goal="Review files", priority=80))
        router = RouterAgent(
            StaticLLMClient([
                {
                    "assignments": [
                        {
                            "todo_id": first.todo_id,
                            "worker_name": "recon-worker",
                            "rationale": "scope mapping",
                        },
                        {
                            "todo_id": second.todo_id,
                            "worker_name": "artifact-worker",
                            "rationale": "file review",
                        },
                    ],
                    "rationale": "parallel concerns, sequential execution",
                }
            ])
        )

        decision = router.route(
            state,
            worker_catalog=[
                {"name": "recon-worker"},
                {"name": "artifact-worker"},
            ],
            max_assignments=5,
        )

        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(first.todo_id, "recon-worker"), (second.todo_id, "artifact-worker")],
        )

    def test_routes_only_one_focus_phase_per_round(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        recon = state.queue_todo(TodoItem(goal="Map scope", phase=TodoPhase.RECON, priority=50))
        exploit = state.queue_todo(
            TodoItem(goal="Exploit confirmed issue", phase=TodoPhase.EXPLOIT, priority=100)
        )
        captured: dict[str, object] = {}

        def respond(system_prompt: str, user_prompt: str):
            del system_prompt
            snapshot = json.loads(user_prompt)
            captured.update(snapshot)
            ready = snapshot["ready_todos"]
            return {
                "assignments": [
                    {
                        "todo_id": ready[0]["todo_id"],
                        "worker_name": "recon-worker",
                        "rationale": "earliest phase first",
                    }
                ],
                "rationale": "single phase",
            }

        router = RouterAgent(StaticLLMClient(respond))

        decision = router.route(
            state,
            worker_catalog=[
                {"name": "recon-worker"},
                {"name": "exploit-worker"},
            ],
            max_assignments=5,
        )

        self.assertEqual([todo["todo_id"] for todo in captured["ready_todos"]], [recon.todo_id])
        self.assertNotIn(exploit.todo_id, [todo["todo_id"] for todo in captured["ready_todos"]])
        self.assertEqual(decision.assignments[0].todo_id, recon.todo_id)

    def test_short_results_are_returned_directly_without_llm_summary(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        router = RouterAgent(StaticLLMClient([]))
        summary = router.summarize_round(
            state,
            results=[
                WorkerResult(todo_id="todo-1", worker_name="recon-worker", success=True, summary="mapped"),
                WorkerResult(todo_id="todo-2", worker_name="artifact-worker", success=True, summary="reviewed"),
            ],
        )

        self.assertFalse(summary.used_llm)
        self.assertIn("mapped", summary.summary)
        self.assertEqual(len(summary.direct_results), 2)

    def test_long_results_trigger_llm_summary(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        router = RouterAgent(
            StaticLLMClient([
                {
                    "summary": "compressed",
                    "direct_results": [],
                    "key_findings": ["important"],
                    "next_focus": "validate",
                    "used_llm": True,
                }
            ])
        )
        summary = router.summarize_round(
            state,
            results=[
                WorkerResult(
                    todo_id=f"todo-{idx}",
                    worker_name="artifact-worker",
                    success=True,
                    summary="x" * 1200,
                )
                for idx in range(4)
            ],
        )

        self.assertTrue(summary.used_llm)
        self.assertEqual(summary.summary, "compressed")


if __name__ == "__main__":
    unittest.main()
