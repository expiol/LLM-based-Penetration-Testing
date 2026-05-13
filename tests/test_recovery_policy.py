"""Tests for RAG-driven solver recovery."""

from __future__ import annotations

import unittest

from killchain_docker.knowledge import RagContext, RagHit
from killchain_docker.orchestrator.recovery import RecoveryPolicy
from killchain_docker.state import ExecutionRecord, GlobalState, Task


def _stfu_hit(score: float) -> RagHit:
    return RagHit(
        challenge_id="2013f-cry-stfu",
        name="stfu",
        category="crypto",
        year="2013",
        event="CSAW-Finals",
        description="LFSR-based stream cipher with header fields.",
        files=["stfu", "flag.stfu"],
        solution_sketch="Read seed/tap/skip from header, calibrate LFSR, XOR keystream.",
        score=score,
    )


class _StubAugmenter:
    def __init__(self, *, score: float) -> None:
        self._score = score

    @property
    def enabled(self) -> bool:
        return True

    def context_for(self, _state: GlobalState) -> RagContext:
        hit = _stfu_hit(self._score)
        return RagContext(
            enabled=True,
            top_score=self._score,
            top_challenge_id=hit.challenge_id,
            exact_self_hit=True,
            hits=[hit],
        )


def _state() -> GlobalState:
    return GlobalState(
        objective="Solve stfu.",
        authorized_scope=[],
        metadata={
            "challenge": {
                "name": "stfu",
                "category": "crypto",
                "files": ["stfu", "flag.stfu"],
                "canonical_name": "2013f-cry-stfu",
            }
        },
    )


def _push_solver_failures(state: GlobalState, count: int) -> None:
    for idx in range(count):
        state.execution_log.append(
            ExecutionRecord(
                task_id=f"solver-{idx}",
                worker_name="solver-agent",
                success=False,
                summary=(
                    "Solver execution failed: timeout after 180s. "
                    "Skip: 1082458112. exit code -1"
                ),
                error=None,
            )
        )


class RecoveryPolicyTests(unittest.TestCase):
    def test_high_confidence_rag_solver_streak_creates_recovery_task(self) -> None:
        state = _state()
        _push_solver_failures(state, 8)
        policy = RecoveryPolicy(augmenter=_StubAugmenter(score=0.75), emit=lambda _: None)

        result = policy.apply(state)

        self.assertTrue(result.created)
        task = result.task
        self.assertIsNotNone(task)
        assert task is not None
        self.assertEqual(task.task_type, "solve.generate_script")
        self.assertEqual(task.priority, 100)
        self.assertEqual(task.input_context["solver_mode"], "recovery")
        # Generic timeout classification — no challenge-specific class names.
        self.assertEqual(task.input_context["failure_class"], "timeout")
        checks = task.input_context["required_checks"]
        self.assertTrue(any("timeout" in c.lower() for c in checks))

    def test_existing_recovery_task_prevents_duplicate(self) -> None:
        state = _state()
        _push_solver_failures(state, 8)
        state.queue_task(
            Task(
                title="Existing recovery",
                description="already queued",
                task_type="solve.generate_script",
                priority=100,
                input_context={"solver_mode": "recovery", "files_root": "/tmp"},
            )
        )
        policy = RecoveryPolicy(augmenter=_StubAugmenter(score=0.8), emit=lambda _: None)

        result = policy.apply(state)

        self.assertFalse(result.created)
        recovery_tasks = [
            task
            for task in state.task_chain.tasks
            if task.input_context.get("solver_mode") == "recovery"
        ]
        self.assertEqual(len(recovery_tasks), 1)

    def test_low_rag_score_does_not_trigger_recovery(self) -> None:
        state = _state()
        _push_solver_failures(state, 8)
        policy = RecoveryPolicy(augmenter=_StubAugmenter(score=0.2), emit=lambda _: None)

        result = policy.apply(state)

        self.assertFalse(result.created)
        self.assertFalse(state.task_chain.tasks)

    def test_streak_with_high_rag_emits_recovery_task(self) -> None:
        state = _state()
        _push_solver_failures(state, 8)

        RecoveryPolicy(augmenter=_StubAugmenter(score=0.9), emit=lambda _: None).apply(state)

        self.assertTrue(
            any(
                task.input_context.get("solver_mode") == "recovery"
                for task in state.task_chain.tasks
            )
        )


if __name__ == "__main__":
    unittest.main()
