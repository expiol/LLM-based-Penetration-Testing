"""Tests for persona worker coverage."""

from __future__ import annotations

import unittest

from killchain_docker.state import RunState, TodoItem
from killchain_docker.tools import ToolCapability
from killchain_docker.workers import all_worker_classes
from killchain_docker.workers.persona import (
    ArtifactWorker,
    ExploitWorker,
    FlagWorker,
    ReconWorker,
    WebWorker,
)


class PersonaWorkerTests(unittest.TestCase):
    def test_all_personas_are_registered(self) -> None:
        self.assertEqual(
            all_worker_classes(),
            [ReconWorker, ArtifactWorker, WebWorker, ExploitWorker, FlagWorker],
        )

    def test_personas_cover_expected_capability_groups(self) -> None:
        self.assertIn(ToolCapability.HTTP_METADATA, ReconWorker.allowed_capabilities)
        self.assertIn(ToolCapability.ARTIFACT_TRIAGE, ArtifactWorker.allowed_capabilities)
        self.assertIn(ToolCapability.HTTP_CONTENT, WebWorker.allowed_capabilities)
        self.assertIn(ToolCapability.EXPLOIT_PROBE, ExploitWorker.allowed_capabilities)
        self.assertIn(ToolCapability.FLAG_HARVEST, FlagWorker.allowed_capabilities)

    def test_persona_names_are_router_facing(self) -> None:
        self.assertEqual(
            [cls.name for cls in all_worker_classes()],
            ["recon-worker", "artifact-worker", "web-worker", "exploit-worker", "flag-worker"],
        )

    def test_tool_selected_metadata_cannot_override_todo_context(self) -> None:
        worker = WebWorker()
        metadata = worker._prepare_metadata(
            capability=ToolCapability.HTTP_CONTENT,
            todo=TodoItem(
                goal="Review known page",
                context={"base_url": "http://safe.test", "paths": ["/admin"]},
            ),
            state=RunState(objective="Solve.", authorized_scope=["http://safe.test"]),
            selected_metadata={"base_url": "http://outside.test", "paths": ["/evil"]},
        )

        self.assertEqual(metadata["base_url"], "http://safe.test")
        self.assertEqual(metadata["paths"], ["/admin"])


if __name__ == "__main__":
    unittest.main()
