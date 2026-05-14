"""Tests for dispatch policy hard guardrails."""

from __future__ import annotations

import unittest

from killchain_docker.orchestrator.dispatch_policy import DispatchPolicy
from killchain_docker.state.models import (
    ExecutionRecord,
    GlobalState,
    Task,
)


def _state_with_tasks(tasks: list[Task]) -> GlobalState:
    state = GlobalState(objective="x", authorized_scope=[])
    for task in tasks:
        state.queue_task(task)
    return state


def _artifact_task(idx: int, *, priority: int = 90) -> Task:
    return Task(
        title=f"Review #{idx}",
        description=f"artifact review {idx}",
        task_type="artifact.source_review",
        priority=priority,
        input_context={"files_root": "/tmp", "source_files": [f"{idx}.py"]},
    )


def _validate_task(idx: int, candidate: str | None = None) -> Task:
    return Task(
        title=f"Validate #{idx}",
        description=f"validate {idx}",
        task_type="flag.validate",
        priority=99,
        input_context={"candidate_flag": candidate or f"flag{{cand_{idx}}}"},
    )


class TestPlannerSelectedBatch(unittest.TestCase):
    def test_selected_task_ids_control_dispatch_order(self) -> None:
        tasks = [_artifact_task(i) for i in range(3)]
        state = _state_with_tasks(tasks)
        policy = DispatchPolicy(emit=lambda _: None)
        batch = policy.dequeue_batch(
            state,
            selected_task_ids=[tasks[2].task_id, tasks[0].task_id],
        ).tasks
        self.assertEqual([task.task_id for task in batch], [tasks[2].task_id, tasks[0].task_id])

    def test_invalid_selected_ids_are_withheld(self) -> None:
        state = _state_with_tasks([_artifact_task(0)])
        policy = DispatchPolicy(emit=lambda _: None)
        result = policy.dequeue_batch(state, selected_task_ids=["not-ready"])
        self.assertEqual(result.tasks, [])
        self.assertTrue(result.withheld_due_to_policy)

    def test_validates_use_batchable_cap(self) -> None:
        # Eight validate tasks — only 5 (the new batchable cap) per cycle.
        state = _state_with_tasks(
            [_validate_task(i, f"flag{{cand_{i}}}") for i in range(8)]
        )
        policy = DispatchPolicy(emit=lambda _: None)
        batch = policy.dequeue_batch(state).tasks
        self.assertEqual(
            sum(1 for t in batch if t.task_type == "flag.validate"), 5
        )

    def test_truly_idle_queue_reports_not_withheld(self) -> None:
        policy = DispatchPolicy(emit=lambda _: None)
        result = policy.dequeue_batch(_state_with_tasks([]))
        self.assertEqual(result.tasks, [])
        self.assertFalse(result.withheld_due_to_policy)


class TestDispatchValidationSuppression(unittest.TestCase):
    def _push_validation_failure(
        self, state: GlobalState, summary: str, *, error: str | None = None,
    ) -> None:
        state.execution_log.append(
            ExecutionRecord(
                task_id=f"task-{len(state.execution_log)}",
                worker_name="flag-validation-agent",
                success=False,
                summary=summary,
                error=error,
            )
        )

    def test_validation_failure_streak_suppresses_validate(self) -> None:
        task = _validate_task(0)
        state = _state_with_tasks([task])
        for _ in range(8):
            self._push_validation_failure(
                state,
                "candidate rejected",
            )
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(
            state,
            selected_task_ids=[task.task_id],
        )
        self.assertEqual(dq.tasks, [])
        self.assertTrue(dq.withheld_due_to_policy)


if __name__ == "__main__":
    unittest.main()
