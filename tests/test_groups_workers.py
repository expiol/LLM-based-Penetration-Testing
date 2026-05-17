"""Tests for persona worker coverage — updated for unified Worker architecture."""

from __future__ import annotations

import unittest

from killchain_docker.tools import ToolCapability
from killchain_docker.workers import BUILTIN_WORKER_SPECS, WorkerBuildContext, build_builtin_workers
from killchain_docker.llm import StaticLLMClient
from killchain_docker.tools import ExecutionPlane


class PersonaWorkerTests(unittest.TestCase):
    def test_all_personas_are_registered(self) -> None:
        self.assertEqual(
            [spec.key for spec in BUILTIN_WORKER_SPECS],
            ["recon-worker", "artifact-worker", "web-worker", "exploit-worker", "flag-worker"],
        )

    def test_all_personas_have_universal_capabilities(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
        )
        for spec in BUILTIN_WORKER_SPECS:
            worker = spec.build(context)
            self.assertIn(ToolCapability.SHELL_EXEC, worker.allowed_capabilities)
            self.assertIn(ToolCapability.SCRIPT_EXEC, worker.allowed_capabilities)

    def test_persona_names_are_router_facing(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
        )
        names = [spec.build(context).name for spec in BUILTIN_WORKER_SPECS]
        self.assertEqual(
            names,
            ["recon-worker", "artifact-worker", "web-worker", "exploit-worker", "flag-worker"],
        )


if __name__ == "__main__":
    unittest.main()
