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
        recon = state.queue_todo(TodoItem(goal="Collect baseline", phase=TodoPhase.RECON, priority=50))
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

    def test_llm_route_respected_for_analysis_tasks(self) -> None:
        """LLM routing decisions are trusted — no deterministic override."""
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(
            TodoItem(
                goal="Analyze bundled binary.",
                phase=TodoPhase.ANALYSIS,
                context={"binary_files": ["stfu"]},
            )
        )
        router = RouterAgent(
            StaticLLMClient([
                {
                    "assignments": [
                        {
                            "todo_id": todo.todo_id,
                            "worker_name": "artifact-worker",
                            "rationale": "file analysis",
                        }
                    ],
                    "rationale": "LLM route",
                }
            ])
        )

        decision = router.route(
            state,
            worker_catalog=[
                {"name": "artifact-worker"},
                {"name": "flag-worker"},
            ],
            max_assignments=5,
        )

        self.assertEqual(decision.assignments[0].worker_name, "artifact-worker")

    def test_llm_route_passes_through_without_override(self) -> None:
        """LLM routing is trusted — no policy override of worker assignments."""
        state = RunState(objective="Solve.", authorized_scope=[])
        scoped = state.queue_todo(TodoItem(goal="Map scope", phase=TodoPhase.RECON, priority=90))
        generic = state.queue_todo(TodoItem(goal="Review notes", phase=TodoPhase.RECON, priority=80))
        router = RouterAgent(
            StaticLLMClient([
                {
                    "assignments": [
                        {
                            "todo_id": scoped.todo_id,
                            "worker_name": "artifact-worker",
                            "rationale": "LLM chose artifact",
                        },
                        {
                            "todo_id": generic.todo_id,
                            "worker_name": "artifact-worker",
                            "rationale": "LLM chose artifact",
                        },
                    ],
                    "rationale": "LLM route",
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
            [(scoped.todo_id, "artifact-worker"), (generic.todo_id, "artifact-worker")],
        )

    def test_empty_llm_route_returns_no_valid_assignments(self) -> None:
        """When LLM returns no assignments, router returns empty decision (no raise)."""
        state = RunState(objective="Solve.", authorized_scope=[])
        state.queue_todo(TodoItem(goal="Review notes", phase=TodoPhase.RECON))
        router = RouterAgent(
            StaticLLMClient([
                {
                    "assignments": [],
                    "rationale": "no useful assignment",
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
        self.assertEqual(decision.assignments, [])
        self.assertIn("No valid", decision.rationale)

    def test_router_prompt_bounds_ready_todo_context(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        huge_text = "X" * 5000
        todo = state.queue_todo(
            TodoItem(
                goal="Route large context.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "crypto-decrypt",
                    "blob": huge_text,
                    "items": [huge_text for _ in range(20)],
                },
            )
        )
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str):
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "assignments": [
                    {
                        "todo_id": todo.todo_id,
                        "worker_name": "artifact-worker",
                        "rationale": "bounded context",
                    }
                ],
                "rationale": "bounded context",
            }

        router = RouterAgent(StaticLLMClient(respond))

        router.route(
            state,
            worker_catalog=[{"name": "artifact-worker"}],
            max_assignments=5,
        )

        ready = captured["snapshot"]["ready_todos"]  # type: ignore[index]
        context = ready[0]["context"]  # type: ignore[index]
        self.assertLessEqual(len(context["blob"]), 400)
        self.assertEqual(len(context["items"]), 8)
        self.assertNotIn("X" * 1000, json.dumps(captured["snapshot"]))

    def test_deterministic_flag_validation_route(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(
            TodoItem(
                goal="Validate candidate.",
                phase=TodoPhase.FLAG_VALIDATION,
                context={"candidate_flag": "flag{candidate_body}"},
            )
        )
        router = RouterAgent(StaticLLMClient([]))

        decision = router.route(
            state,
            worker_catalog=[{"name": "flag-worker"}, {"name": "artifact-worker"}],
            max_assignments=5,
        )

        self.assertEqual([(item.todo_id, item.worker_name) for item in decision.assignments], [(todo.todo_id, "flag-worker")])

    def test_flag_validation_phase_structurally_routes_to_flag_worker(self) -> None:
        """FLAG_VALIDATION phase todos are structurally routed to flag-worker without LLM."""
        state = RunState(
            objective="Solve.",
            authorized_scope=[],
            metadata={"challenge": {"flag_format": ""}},
        )
        todo = state.queue_todo(
            TodoItem(
                goal="Validate recovered token.",
                phase=TodoPhase.FLAG_VALIDATION,
                context={"candidate_flag": "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"},
            )
        )
        router = RouterAgent(StaticLLMClient([]))

        decision = router.route(
            state,
            worker_catalog=[{"name": "flag-worker"}, {"name": "artifact-worker"}],
            max_assignments=5,
        )

        self.assertEqual([(item.todo_id, item.worker_name) for item in decision.assignments], [(todo.todo_id, "flag-worker")])

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
