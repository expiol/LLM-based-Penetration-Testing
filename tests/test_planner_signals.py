"""Planner signal and run-memory state contract tests."""

from __future__ import annotations

import unittest

from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.state import GlobalState, Task, WorkerReport


class PlannerSignalContractTests(unittest.TestCase):
    def test_worker_report_planner_signals_do_not_queue_items(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])
        task = state.queue_task(Task(
            title="Review",
            description="review",
            task_type="artifact.source_review",
            input_context={"files_root": "/tmp", "source_files": ["a.py"]},
        ))
        suggested = Task(
            title="Validate",
            description="validate",
            task_type="flag.validate",
            input_context={"candidate_flag": "flag{ok}"},
        )
        report = WorkerReport(
            task_id=task.task_id,
            worker_name="source-review-agent",
            success=True,
            summary="found a candidate",
            planner_signals=planner_signals_for_tasks(
                source_task=task,
                worker_name="source-review-agent",
                tasks=[suggested],
            ),
        )

        state.apply_worker_report(report)

        self.assertEqual(len(state.task_chain.tasks), 1)
        self.assertEqual(len(state.planner_signals), 1)
        self.assertEqual(
            state.planner_signals[0].suggested_task_type,
            "flag.validate",
        )

    def test_run_memory_defaults_are_bounded_fields(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])

        self.assertEqual(state.run_memory.long_term_summary, "")
        self.assertEqual(state.run_memory.confirmed_facts, [])
        self.assertEqual(state.run_memory.open_questions, [])
        self.assertEqual(state.run_memory.dead_ends, [])
        self.assertEqual(state.run_memory.current_focus, "")


if __name__ == "__main__":
    unittest.main()
