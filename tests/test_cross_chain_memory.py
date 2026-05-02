"""Regression tests for cross-chain solver memory (fix #6).

When the LLM planner proposes a brand-new ``solve.generate_script`` task
(separate chain from the previous solver retries), the worker should still
see the last 3 failed attempts of the same task_type so it doesn't repeat
what the previous chain just tried.  This is what was missing in the
``2013f-web-historypeats`` run: 22 unique solver titles, none inheriting
the previous chain's stdout/stderr fingerprint.
"""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidenceComposer
from nyuctf_mutil_killchain.state.models import (
    GlobalState,
    Task,
    WorkerReport,
)


def _state_with_challenge(category: str = "web") -> GlobalState:
    return GlobalState(
        objective="Solve x.",
        authorized_scope=[],
        metadata={
            "challenge": {
                "name": "x",
                "category": category,
                "flag_format": "flag{...}",
                "files": ["app.py"],
            }
        },
    )


class TestTaskTypeMemory(unittest.TestCase):
    def test_failed_solver_recorded_into_memory(self) -> None:
        state = _state_with_challenge()
        first = Task(
            title="Comprehensive script",
            description="solver",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
        )
        state.queue_task(first)
        report = WorkerReport(
            task_id=first.task_id,
            worker_name="solver-agent",
            success=False,
            summary="Solver execution ran without recovering a flag.",
            output_context={"stdout": "main page status: 200", "stderr": ""},
            error="exit 0 with empty stdout",
        )
        state.apply_worker_report(report)
        memory = state.task_type_memory.get("solve.generate_script") or []
        self.assertEqual(len(memory), 1)
        self.assertIn("ran without recovering", memory[0].summary)

    def test_fresh_chain_inherits_previous_chain_attempts(self) -> None:
        state = _state_with_challenge()
        first = Task(
            title="Comprehensive script",
            description="solver",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
        )
        state.queue_task(first)
        state.apply_worker_report(
            WorkerReport(
                task_id=first.task_id,
                worker_name="solver-agent",
                success=False,
                summary="Solver execution ran without recovering a flag.",
                output_context={
                    "stdout": "Tried admin=true cookie",
                    "stderr": "",
                    "solver_code_preview": "import requests\\n# tried 5 cookies",
                },
                error="exit 0 with empty stdout",
            )
        )

        # New planner-proposed task, NO previous_attempts in input_context.
        second = Task(
            title="Different angle",
            description="solver fresh",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},  # empty previous_attempts
        )
        state.queue_task(second)

        evidence = SolverEvidenceComposer().compose(second, state)
        # Cross-chain memory must surface as previous_attempts so the LLM
        # sees what the previous chain did.
        self.assertEqual(len(evidence.previous_attempts), 1)
        self.assertEqual(
            evidence.previous_attempts[0]["source"], "cross_chain_memory"
        )
        self.assertIn("ran without recovering", evidence.previous_attempts[0]["summary"])

    def test_in_chain_attempts_take_precedence(self) -> None:
        state = _state_with_challenge()
        # Pretend the previous chain already failed.
        first = Task(
            title="Old chain",
            description="solver",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
        )
        state.queue_task(first)
        state.apply_worker_report(
            WorkerReport(
                task_id=first.task_id,
                worker_name="solver-agent",
                success=False,
                summary="cross-chain summary",
            )
        )

        # New retry task in the SAME chain — input_context.previous_attempts is set.
        retry = Task(
            title="Retry",
            description="solver",
            task_type="solve.generate_script",
            input_context={
                "files_root": "/tmp",
                "previous_attempts": [
                    {
                        "attempt": 1,
                        "summary": "in-chain summary",
                        "stderr": "in-chain stderr",
                        "error_fingerprint": "in-chain fingerprint",
                    }
                ],
            },
        )
        state.queue_task(retry)
        evidence = SolverEvidenceComposer().compose(retry, state)
        # In-chain context wins; cross-chain memory is NOT mixed in.
        self.assertEqual(len(evidence.previous_attempts), 1)
        self.assertEqual(evidence.previous_attempts[0]["summary"], "in-chain summary")

    def test_memory_capped(self) -> None:
        from nyuctf_mutil_killchain.state.models import TASK_TYPE_MEMORY_LIMIT

        state = _state_with_challenge()
        for i in range(TASK_TYPE_MEMORY_LIMIT + 5):
            t = Task(
                title=f"Task {i}",
                description="solver",
                task_type="solve.generate_script",
                input_context={"files_root": "/tmp"},
            )
            state.queue_task(t)
            state.apply_worker_report(
                WorkerReport(
                    task_id=t.task_id,
                    worker_name="solver-agent",
                    success=False,
                    summary=f"failure {i}",
                )
            )
        memory = state.task_type_memory["solve.generate_script"]
        self.assertEqual(len(memory), TASK_TYPE_MEMORY_LIMIT)
        # FIFO trim: the latest entries are kept, oldest are dropped.
        self.assertEqual(memory[-1].summary, f"failure {TASK_TYPE_MEMORY_LIMIT + 4}")


if __name__ == "__main__":
    unittest.main()
