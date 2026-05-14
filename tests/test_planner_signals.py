"""Worker-to-planner contract tests for the persona runtime."""

from __future__ import annotations

import unittest

from killchain_docker.state import RunState, TodoItem, WorkerResult


class WorkerSuggestionContractTests(unittest.TestCase):
    def test_worker_suggested_todos_do_not_queue_items_directly(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Review files"))
        suggested = TodoItem(goal="Validate candidate", context={"candidate_flag": "flag{ok}"})
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="artifact-worker",
            success=True,
            summary="found a candidate",
            suggested_todos=[suggested],
        )

        state.apply_worker_result(result)

        self.assertEqual(len(state.todos), 1)
        self.assertEqual(state.todos[0].status, "completed")

    def test_run_state_summary_has_bounded_runtime_fields(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        summary = state.summary()

        self.assertEqual(summary["todos"], 0)
        self.assertEqual(summary["rounds"], 0)
        self.assertEqual(summary["executions"], 0)


if __name__ == "__main__":
    unittest.main()

