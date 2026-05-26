"""Tests for persona worker coverage."""

from __future__ import annotations

import unittest

from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.personas.catalog import (
    ALL_PERSONAS,
    WorkerBuildContext,
    build_builtin_workers,
)
from killchain_docker.llm.gateway import StaticLLMClient
from killchain_docker.tools.core import ExecutionPlane


class PersonaWorkerTests(unittest.TestCase):
    def test_all_personas_are_registered(self) -> None:
        self.assertEqual(
            [persona.name for persona in ALL_PERSONAS],
            [
                "recon-worker",
                "artifact-worker",
                "web-worker",
                "exploit-worker",
                "flag-worker",
            ],
        )

    def test_all_personas_have_universal_capabilities(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
        )
        for worker in build_builtin_workers(context):
            self.assertIn(ToolCapability.SHELL_EXEC, worker.allowed_capabilities)
            self.assertIn(ToolCapability.SCRIPT_EXEC, worker.allowed_capabilities)

    def test_persona_names_are_router_facing(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
        )
        names = [worker.name for worker in build_builtin_workers(context)]
        self.assertEqual(
            names,
            [
                "recon-worker",
                "artifact-worker",
                "web-worker",
                "exploit-worker",
                "flag-worker",
            ],
        )


if __name__ == "__main__":
    unittest.main()
