"""Tests for orchestrator loop resilience.

Worker-level ``LLMClientError`` must NOT abort the entire run; it should mark
the offending task FAILED and let the run continue so the planner has a chance
to replan around it.  Only planner / router LLM errors are fatal.
"""

from __future__ import annotations

import unittest
from collections.abc import Iterable

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClientError
from nyuctf_mutil_killchain.orchestrator.loop import Orchestrator
from nyuctf_mutil_killchain.orchestrator.planning import (
    PlannedTask,
    PlannerDecision,
    TaskPlanner,
)
from nyuctf_mutil_killchain.state import (
    GlobalState,
    RunStatus,
    Task,
    TaskErrorCode,
    TaskStatus,
    WorkerReport,
)


class _ScriptedPlanner(TaskPlanner):
    """Returns a pre-canned PlannerDecision per cycle, then empty plans."""

    def __init__(self, scripts: Iterable[PlannerDecision]) -> None:
        self._scripts = list(scripts)
        self._cursor = 0

    def plan(self, state: GlobalState) -> PlannerDecision:
        if self._cursor < len(self._scripts):
            decision = self._scripts[self._cursor]
            self._cursor += 1
            return decision
        return PlannerDecision(summary="no more tasks", tasks=[], notes=[], stop_run=False)


class _RaisingWorker(WorkerAgent):
    """Worker that always raises ``LLMClientError`` on ``run``."""

    name = "raising-worker"
    supported_task_types = ("solve.generate_script",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:  # pragma: no cover - never
        raise LLMClientError("synthetic worker LLM failure", transient=False)


class _SuccessWorker(WorkerAgent):
    """Worker that always succeeds; used to confirm the loop kept running."""

    name = "success-worker"
    supported_task_types = ("artifact.triage",)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary="ok",
        )


def _planned(task_type: str, dedupe_key: str) -> PlannedTask:
    return PlannedTask(
        title=f"t-{dedupe_key}",
        description="d",
        task_type=task_type,
        input_context={"files_root": "/home/ctfplayer/ctf_files"},
        dedupe_key=dedupe_key,
    )


def _state() -> GlobalState:
    return GlobalState(
        objective="resilience smoke",
        authorized_scope=[],
        metadata={
            "challenge": {
                "name": "test", "category": "misc",
                "flag_format": "flag{...}", "files": [],
            }
        },
    )


class WorkerLLMErrorIsNonFatalTests(unittest.TestCase):
    def test_raising_worker_does_not_stop_run(self):
        events: list[str] = []
        planner = _ScriptedPlanner([
            PlannerDecision(
                summary="cycle 1",
                tasks=[_planned("solve.generate_script", "solver-1")],
            ),
            PlannerDecision(
                summary="cycle 2",
                tasks=[_planned("artifact.triage", "triage-1")],
            ),
        ])
        orchestrator = Orchestrator(
            state=_state(),
            workers=[_RaisingWorker(), _SuccessWorker()],
            planner=planner,
            emit=events.append,
        )

        final_state = orchestrator.run(max_cycles=4)

        # Run was NOT stopped because of the worker error.
        self.assertNotEqual(final_state.status, RunStatus.STOPPED)
        # The failing task was marked FAILED with the dedicated error_code.
        failing = next(t for t in final_state.task_chain.tasks if t.dedupe_key == "solver-1")
        self.assertEqual(failing.status, TaskStatus.FAILED)
        self.assertEqual(failing.error_code, TaskErrorCode.WORKER_LLM_ERROR)
        # And the subsequent cycle's task did get dispatched and completed.
        triage_task = next(t for t in final_state.task_chain.tasks if t.dedupe_key == "triage-1")
        self.assertEqual(triage_task.status, TaskStatus.COMPLETED)
        # Loop emitted the LLM ERROR diagnostic but DID NOT include "stopping run".
        joined = "\n".join(events)
        self.assertIn("LLM ERROR in raising-worker", joined)
        self.assertNotIn("stopping run", joined)


if __name__ == "__main__":
    unittest.main()
