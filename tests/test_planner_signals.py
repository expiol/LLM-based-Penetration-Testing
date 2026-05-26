"""Worker-to-planner contract tests for the persona runtime."""

from __future__ import annotations
import unittest
from killchain_docker.orchestrator.todo.queue import TodoQueue as todo_queue
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.state_delta import StateDeltaApplier
from killchain_docker.state.worker_results import WorkerResultApplier


class WorkerSuggestionContractTests(unittest.TestCase):
    def test_worker_suggested_todos_do_not_queue_items_directly(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(TodoItem(goal="Review files"))
        suggested = TodoItem(
            goal="Validate candidate", context={"candidate_flag": "flag{ok}"}
        )
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="artifact-worker",
            success=True,
            summary="found a candidate",
            suggested_todos=[suggested],
        )
        WorkerResultApplier(state).apply(result)
        self.assertEqual(len(state.todos), 1)
        self.assertEqual(state.todos[0].status, "completed")

    def test_report_projection_summary_has_bounded_runtime_fields(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        summary = RunReportProjection(state).summary()
        self.assertEqual(summary["todos"], 0)
        self.assertEqual(summary["rounds"], 0)
        self.assertEqual(summary["executions"], 0)


if __name__ == "__main__":
    unittest.main()
