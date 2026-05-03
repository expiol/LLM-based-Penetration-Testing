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


class TestSolverStreakSuppression(unittest.TestCase):
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

    def _push_other_worker(
        self, state: GlobalState, worker: str = "web-content-agent", success: bool = True,
    ) -> None:
        state.execution_log.append(
            ExecutionRecord(
                task_id=f"task-{len(state.execution_log)}",
                worker_name=worker,
                success=success,
                summary=f"{worker} did something",
                error=None,
            )
        )

    def test_four_consecutive_no_progress_suppresses_solve(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        # Push 4 solver runs that "ran without recovering a flag".
        for _ in range(4):
            self._push_solver_failure(
                state,
                "Solver execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
            )
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(state)
        self.assertEqual([t for t in dq.tasks if t.task_type.startswith("solve.")], [])
        self.assertTrue(
            dq.withheld_due_to_policy,
            "ready solve tasks withheld by suppression should set withheld_due_to_policy",
        )

    def test_unrelated_worker_records_do_not_reset_streak(self) -> None:
        """Regression for historypeats / onlythisprogram: solver streak is
        the count of consecutive *solver* failures, regardless of unrelated
        web/source/computation records sandwiched between them."""

        state = _state_with_tasks([_solve_task(0)])
        # Pattern observed in real logs: solver fails, web-path-probe
        # succeeds, solver fails again, web-content-agent succeeds, ...
        for _ in range(4):
            self._push_solver_failure(
                state,
                "Solver execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
            )
            self._push_other_worker(state, "web-path-probe-agent", success=True)
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(state)
        self.assertEqual(
            [t for t in dq.tasks if t.task_type.startswith("solve.")], [],
            "interleaved web-probe successes must NOT reset the solver streak",
        )

    def test_llm_error_summary_counts_toward_streak(self) -> None:
        """LLMClientError-style failures (empty body, missing field, lint
        exhausted) must count toward the solver streak — they previously
        dropped through unnoticed."""

        state = _state_with_tasks([_solve_task(0)])
        fingerprints = [
            "Worker solver-agent raised LLMClientError; replan needed.",
            "Solver execution failed: LLM solver_code failed in-process lint after 5 attempt(s).",
            "Solver execution failed (exit 1): exit code 1, 0 flag candidate(s).",
            "Solver execution ran without recovering a flag: exit code 0.",
        ]
        for summary in fingerprints:
            self._push_solver_failure(state, summary)
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(state)
        self.assertEqual([t for t in dq.tasks if t.task_type.startswith("solve.")], [])

    def test_solver_success_resets_streak(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        for _ in range(3):
            self._push_solver_failure(
                state, "Solver execution ran without recovering a flag.",
            )
        # A solver SUCCESS resets the streak (validation will pick up the flag).
        state.execution_log.append(
            ExecutionRecord(
                task_id="task-solver-ok",
                worker_name="solver-agent",
                success=True,
                summary="Solver execution succeeded: 3 flag candidate(s).",
                error=None,
            )
        )
        # Three more failures after the success — streak below limit, no suppression.
        for _ in range(3):
            self._push_solver_failure(
                state, "Solver execution ran without recovering a flag.",
            )
        policy = DispatchPolicy(emit=lambda _: None)
        dq = policy.dequeue_batch(state)
        self.assertTrue(
            any(t.task_type.startswith("solve.") for t in dq.tasks),
            "solver streak should reset on solver success, even with 3 failures after",
        )

    def test_progress_resets_streak(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        # 3 fails, then a non-solver task succeeds — streak should NOT
        # reset on non-solver work, but neither should it reach the limit.
        for _ in range(3):
            self._push_solver_failure(
                state, "Solver execution ran without recovering a flag: exit code 0.",
            )
        self._push_other_worker(state, "source-review-agent", success=True)
        policy = DispatchPolicy(emit=lambda _: None)
        batch = policy.dequeue_batch(state).tasks
        self.assertTrue(
            any(t.task_type.startswith("solve.") for t in batch),
            "below-limit solver streak should not block dispatch",
        )


class _StubAugmenter:
    """Minimal augmenter double for streak-suppression tests.

    Exposes only the ``enabled`` / ``top_score`` surface that
    :class:`DispatchPolicy` consumes — keeps tests free of fastembed
    dependency.
    """

    def __init__(self, *, enabled: bool, top_score: float) -> None:
        self._enabled = enabled
        self._top_score = top_score

    @property
    def enabled(self) -> bool:
        return self._enabled

    def top_score(self, _state) -> float:
        return self._top_score


class TestRagAwareSolverStreak(unittest.TestCase):
    """High-confidence RAG hits relax the solver-streak suppression limit."""

    def _push_failures(self, state: GlobalState, n: int) -> None:
        for _ in range(n):
            state.execution_log.append(
                ExecutionRecord(
                    task_id=f"task-{len(state.execution_log)}",
                    worker_name="solver-agent",
                    success=False,
                    summary="Solver execution ran without recovering a flag: exit code 0.",
                    error=None,
                )
            )

    def test_high_score_grants_extra_retries(self) -> None:
        # 4 fails would normally suppress; a top score of 0.8 should
        # allow at least one more solver task through this cycle.
        state = _state_with_tasks([_solve_task(0)])
        self._push_failures(state, 4)
        policy = DispatchPolicy(
            emit=lambda _: None,
            augmenter=_StubAugmenter(enabled=True, top_score=0.8),
        )
        batch = policy.dequeue_batch(state).tasks
        self.assertTrue(
            any(t.task_type.startswith("solve.") for t in batch),
            "RAG top-1 ≥ HIGH_CONFIDENCE_SCORE should relax the solver streak",
        )

    def test_low_score_keeps_default_limit(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        self._push_failures(state, 4)
        policy = DispatchPolicy(
            emit=lambda _: None,
            augmenter=_StubAugmenter(enabled=True, top_score=0.2),
        )
        dq = policy.dequeue_batch(state)
        self.assertFalse(
            any(t.task_type.startswith("solve.") for t in dq.tasks),
            "weak RAG signals should NOT lift the suppression limit",
        )
        self.assertTrue(dq.withheld_due_to_policy)

    def test_disabled_augmenter_uses_default_limit(self) -> None:
        state = _state_with_tasks([_solve_task(0)])
        self._push_failures(state, 4)
        policy = DispatchPolicy(
            emit=lambda _: None,
            augmenter=_StubAugmenter(enabled=False, top_score=0.0),
        )
        dq = policy.dequeue_batch(state)
        self.assertFalse(
            any(t.task_type.startswith("solve.") for t in dq.tasks),
            "augmenter.enabled=False must fall back to the default streak limit",
        )

    def test_high_score_eventually_suppresses_at_extended_limit(self) -> None:
        # With high RAG score the limit is base+bonus = 4+4 = 8.
        # Eight failures must still cross the threshold.
        state = _state_with_tasks([_solve_task(0)])
        self._push_failures(state, 8)
        policy = DispatchPolicy(
            emit=lambda _: None,
            augmenter=_StubAugmenter(enabled=True, top_score=0.9),
        )
        dq = policy.dequeue_batch(state)
        self.assertFalse(
            any(t.task_type.startswith("solve.") for t in dq.tasks),
            "extended limit must still trip when failures pile up",
        )


if __name__ == "__main__":
    unittest.main()
