"""Regression tests for queue fan-out guards."""

from __future__ import annotations

import unittest

from killchain_docker.state import Asset, AssetKind, GlobalState, Route, Task, TaskStatus
from killchain_docker.state.models import (
    PENDING_EXPLOIT_HYPOTHESIS_LIMIT,
    PENDING_FLAG_VALIDATE_LIMIT,
    PENDING_WEB_CONTENT_LIMIT_PER_ASSET,
    PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET,
    PENDING_WEB_PATH_PROBE_LIMIT_PER_ASSET,
)
from killchain_docker.state.task_factory import build_path_probe_tasks_for_assets
from killchain_docker.tools import ToolCapability


class QueueGuardTests(unittest.TestCase):
    def test_path_probe_factory_skips_known_routes_and_caps_width(self) -> None:
        state = GlobalState(objective="Solve web.", authorized_scope=[])
        state.upsert_asset(
            Asset(
                asset_id="asset-1",
                kind=AssetKind.WEB_APPLICATION,
                base_url="http://example.test",
            )
        )
        state.upsert_route(
            Route(
                asset_ref="asset-1",
                url="http://example.test/admin",
                path="/admin",
                source=ToolCapability.HTTP_PROBE_PATHS.value,
            )
        )

        tasks = build_path_probe_tasks_for_assets(
            state,
            ["/admin", *[f"/candidate-{idx}" for idx in range(20)]],
        )

        self.assertEqual(len(tasks), 1)
        paths = tasks[0].input_context["paths"]
        self.assertNotIn("/admin", paths)
        self.assertLessEqual(len(paths), 12)

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

    def test_web_probe_and_content_pending_caps_are_per_asset(self) -> None:
        state = GlobalState(objective="Solve web.", authorized_scope=[])
        for idx in range(PENDING_WEB_PATH_PROBE_LIMIT_PER_ASSET):
            state.queue_task(
                Task(
                    title="Probe",
                    description="probe",
                    task_type="web.path_probe",
                    input_context={
                        "asset_id": "asset-1",
                        "base_url": "http://x",
                        "paths": [f"/{idx}"],
                    },
                    dedupe_key=f"path:{idx}",
                )
            )
        extra_path = Task(
            title="Probe",
            description="probe",
            task_type="web.path_probe",
            input_context={
                "asset_id": "asset-1",
                "base_url": "http://x",
                "paths": ["/extra"],
            },
            dedupe_key="path:extra",
        )
        self.assertNotEqual(state.queue_task(extra_path).task_id, extra_path.task_id)

        for idx in range(PENDING_WEB_CONTENT_LIMIT_PER_ASSET):
            state.queue_task(
                Task(
                    title="Content",
                    description="content",
                    task_type="web.content_review",
                    input_context={"asset_id": "asset-1", "base_url": f"http://x/{idx}"},
                    dedupe_key=f"content:{idx}",
                )
            )
        extra_content = Task(
            title="Content",
            description="content",
            task_type="web.content_review",
            input_context={"asset_id": "asset-1", "base_url": "http://x/extra"},
            dedupe_key="content:extra",
        )
        self.assertNotEqual(state.queue_task(extra_content).task_id, extra_content.task_id)

    def test_exploit_hypothesis_pending_cap(self) -> None:
        state = GlobalState(objective="Solve.", authorized_scope=[])
        for idx in range(PENDING_EXPLOIT_HYPOTHESIS_LIMIT):
            state.queue_task(
                Task(
                    title="Hypothesis",
                    description="hypothesis",
                    task_type="exploit.hypothesis",
                    input_context={"seed_terms": [str(idx)]},
                    dedupe_key=f"hyp:{idx}",
                )
            )
        extra = Task(
            title="Hypothesis",
            description="hypothesis",
            task_type="exploit.hypothesis",
            input_context={"seed_terms": ["extra"]},
            dedupe_key="hyp:extra",
        )
        self.assertNotEqual(state.queue_task(extra).task_id, extra.task_id)

if __name__ == "__main__":
    unittest.main()
