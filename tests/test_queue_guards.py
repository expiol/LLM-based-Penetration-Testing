"""Regression tests for queue fan-out guards."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.state import GlobalState, Task, TaskStatus
from nyuctf_mutil_killchain.state.models import (
    PENDING_FLAG_VALIDATE_LIMIT,
    PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET,
)


class QueueGuardTests(unittest.TestCase):
    def test_web_form_probe_pending_cap_is_per_asset(self) -> None:
        state = GlobalState(objective="Solve web.", authorized_scope=[])
        for idx in range(PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET):
            state.queue_task(
                Task(
                    title=f"Form {idx}",
                    description="probe",
                    task_type="web.form_probe",
                    input_context={
                        "asset_id": "seed-asset",
                        "page_url": f"http://example.test/{idx}",
                        "forms": [{"method": "post", "inputs": [{"name": "x"}]}],
                    },
                    dedupe_key=f"web-form:{idx}",
                )
            )

        extra = Task(
            title="Extra",
            description="probe",
            task_type="web.form_probe",
            input_context={
                "asset_id": "seed-asset",
                "page_url": "http://example.test/extra",
                "forms": [{"method": "post", "inputs": [{"name": "x"}]}],
            },
            dedupe_key="web-form:extra",
        )
        queued = state.queue_task(extra)

        self.assertNotEqual(queued.task_id, extra.task_id)
        pending = [
            task for task in state.task_chain.tasks
            if task.task_type == "web.form_probe"
            and task.status == TaskStatus.PENDING
            and task.input_context.get("asset_id") == "seed-asset"
        ]
        self.assertEqual(len(pending), PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET)

        other_asset = Task(
            title="Other",
            description="probe",
            task_type="web.form_probe",
            input_context={
                "asset_id": "other-asset",
                "page_url": "http://other.test/",
                "forms": [{"method": "post", "inputs": [{"name": "x"}]}],
            },
            dedupe_key="web-form:other",
        )
        self.assertEqual(state.queue_task(other_asset).task_id, other_asset.task_id)

    def test_flag_validate_pending_cap(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])
        for idx in range(PENDING_FLAG_VALIDATE_LIMIT):
            state.queue_task(
                Task(
                    title="Validate",
                    description="validate",
                    task_type="flag.validate",
                    input_context={"candidate_flag": f"flag{{candidate_{idx}}}"},
                    dedupe_key=f"flag:{idx}",
                )
            )

        extra = Task(
            title="Validate",
            description="validate",
            task_type="flag.validate",
            input_context={"candidate_flag": "flag{extra_candidate}"},
            dedupe_key="flag:extra",
        )
        queued = state.queue_task(extra)

        self.assertNotEqual(queued.task_id, extra.task_id)
        pending = [
            task for task in state.task_chain.tasks
            if task.task_type == "flag.validate"
            and task.status == TaskStatus.PENDING
        ]
        self.assertEqual(len(pending), PENDING_FLAG_VALIDATE_LIMIT)

    def test_planner_solver_is_not_added_when_solver_already_pending(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])
        existing = Task(
            title="Solver",
            description="solve",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
            dedupe_key="solve:existing",
        )
        state.queue_task(existing)

        planner_solver = Task(
            title="Another solver",
            description="solve",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
            dedupe_key="solve:planner",
            metadata={"planned_by": "llm-planner"},
        )
        queued = state.queue_task(planner_solver)

        self.assertEqual(queued.task_id, existing.task_id)
        solvers = [
            task for task in state.task_chain.tasks
            if task.task_type == "solve.generate_script"
        ]
        self.assertEqual(len(solvers), 1)

    def test_solver_retry_and_recovery_bypass_planner_solver_cap(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])
        existing = Task(
            title="Solver",
            description="solve",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp"},
            dedupe_key="solve:existing",
        )
        state.queue_task(existing)

        retry = Task(
            title="Solver retry",
            description="retry",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp", "attempt_number": 2},
            dedupe_key="solve:retry",
            metadata={"planned_by": "solver-agent"},
        )
        recovery = Task(
            title="Solver recovery",
            description="recovery",
            task_type="solve.generate_script",
            input_context={"files_root": "/tmp", "solver_mode": "recovery"},
            dedupe_key="solve:recovery",
            metadata={"planned_by": "recovery-policy"},
        )

        self.assertEqual(state.queue_task(retry).task_id, retry.task_id)
        self.assertEqual(state.queue_task(recovery).task_id, recovery.task_id)
        solvers = [
            task for task in state.task_chain.tasks
            if task.task_type == "solve.generate_script"
        ]
        self.assertEqual(len(solvers), 3)


if __name__ == "__main__":
    unittest.main()
