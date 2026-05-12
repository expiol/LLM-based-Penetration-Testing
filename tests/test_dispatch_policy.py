"""Tests for the dispatch policy: per-prefix caps + anti-spin streak detection."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.orchestrator.dispatch_policy import DispatchPolicy
from nyuctf_mutil_killchain.state.models import (
    ExecutionRecord,
    GlobalState,
    Task,
)


def _state_with_tasks(tasks: list[Task]) -> GlobalState:
    state = GlobalState(objective="x", authorized_scope=[])
    for task in tasks:
        state.queue_task(task)
    return state


def _solve_task(idx: int, *, priority: int = 90) -> Task:
    return Task(
        title=f"Solve #{idx}",
        description=f"solver attempt {idx}",
        task_type="solve.generate_script",
        priority=priority,
        input_context={"files_root": "/tmp"},
    )


def _validate_task(idx: int, candidate: str | None = None) -> Task:
    return Task(
        title=f"Validate #{idx}",
        description=f"validate {idx}",
        task_type="flag.validate",
        priority=99,
        input_context={"candidate_flag": candidate or f"flag{{cand_{idx}}}"},
    )


class TestPerPrefixCaps(unittest.TestCase):
    def test_solve_capped_to_one_per_cycle(self) -> None:
        # Five solver tasks queued — only one should make it into the batch.
        state = _state_with_tasks([_solve_task(i) for i in range(5)])
        policy = DispatchPolicy(emit=lambda _: None)
        batch = policy.dequeue_batch(state).tasks
        solve_tasks = [t for t in batch if t.task_type.startswith("solve.")]
        self.assertEqual(len(solve_tasks), 1)

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

    def test_solver_does_not_starve_other_workers(self) -> None:
        # One solver + one web probe; both should run.
        web_task = Task(
            title="Probe",
            description="probe",
            task_type="web.path_probe",
            priority=80,
            input_context={"asset_id": "x", "base_url": "http://x", "paths": ["/"]},
        )
        state = _state_with_tasks([_solve_task(1), _solve_task(2), web_task])
        policy = DispatchPolicy(emit=lambda _: None)
        batch = policy.dequeue_batch(state).tasks
        types = {t.task_type for t in batch}
        self.assertIn("solve.generate_script", types)
        self.assertIn("web.path_probe", types)

    def test_truly_idle_queue_reports_not_withheld(self) -> None:
        policy = DispatchPolicy(emit=lambda _: None)
        result = policy.dequeue_batch(_state_with_tasks([]))
        self.assertEqual(result.tasks, [])
        self.assertFalse(result.withheld_due_to_policy)


class TestDispatchNoSolverRecovery(unittest.TestCase):
    def _push_solver_failure(
        self, state: GlobalState, summary: str, *, error: str | None = None,
    ) -> None:
        state.execution_log.append(
            ExecutionRecord(
                task_id=f"task-{len(state.execution_log)}",
                worker_name="solver-agent",
                success=False,
                summary=summary,
                error=error,
            )
        )

    def test_solver_failure_streak_does_not_suppress_solve(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        for _ in range(8):
            self._push_solver_failure(
                state,
                "Solver execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
            )
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(state)
        self.assertTrue(
            any(t.task_type.startswith("solve.") for t in dq.tasks)
        )
        self.assertFalse(dq.withheld_due_to_policy)


if __name__ == "__main__":
    unittest.main()
