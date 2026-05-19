"""Prompt bounding invariants for LLM-facing agent payloads."""

from __future__ import annotations

import json
import unittest

from killchain_docker.llm import StaticLLMClient
from killchain_docker.state import ExecutionRecord, RunState, TodoItem, WorkerResult
from killchain_docker.tools import ExecutionPlane, ToolCapability
from killchain_docker.workers.base import WorkerAgent


class _PromptWorker(WorkerAgent):
    name = "prompt-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id,
            worker_name=self.name,
            success=True,
            summary="unused",
        )


class WorkerPromptBoundsTests(unittest.TestCase):
    def test_worker_tool_selection_prompt_bounds_state_sections(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "shell.exec",
                "metadata": {"command": "true"},
                "rationale": "bounded",
                "expected_signal": "exit 0",
            }

        huge_text = "X" * 5000
        state = RunState(objective="Solve.")
        state.working_memory["huge"] = huge_text
        state.execution_log.append(
            ExecutionRecord(
                task_id="todo-huge",
                worker_name="artifact-worker",
                success=False,
                summary=huge_text,
                error=huge_text,
            )
        )
        task = TodoItem(
            goal="Choose a bounded tool call.",
            context={
                "family": "crypto-decrypt",
                "blob": huge_text,
                "items": [huge_text for _ in range(20)],
            },
        )
        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond),
            execution_plane=ExecutionPlane(),
        )

        worker.choose_tool_use(
            task=task,
            state=state,
            allowed_capabilities=[ToolCapability.SHELL_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": huge_text,
                    "stderr_preview": huge_text,
                    "flag_candidates": [],
                    "returncode": 1,
                }
            ],
        )

        snapshot = captured["snapshot"]
        todo_context = snapshot["todo"]["context"]  # type: ignore[index]
        self.assertLessEqual(len(todo_context["blob"]), 460)
        self.assertEqual(len(todo_context["items"]), 8)
        self.assertLessEqual(len(snapshot["working_memory"]["huge"]), 400)  # type: ignore[index]
        recent_failures = snapshot["recent_failures"]  # type: ignore[index]
        self.assertLessEqual(len(recent_failures[0]["summary"]), 360)
        prior_steps = snapshot["prior_steps"]  # type: ignore[index]
        self.assertLessEqual(len(prior_steps[0]["stdout_preview"]), 740)
        correction_context = snapshot["correction_context"]  # type: ignore[index]
        self.assertLessEqual(len(correction_context["last_stdout"]), 740)
        self.assertNotIn("reflexion_context", snapshot)
        self.assertNotIn("X" * 1000, json.dumps(snapshot))


if __name__ == "__main__":
    unittest.main()
