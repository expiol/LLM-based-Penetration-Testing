"""Tests for the persona worker registry."""

from __future__ import annotations

import unittest

from killchain_docker.llm import StaticLLMClient
from killchain_docker.tools import ExecutionPlane
from killchain_docker.workers import (
    BUILTIN_WORKER_SPECS,
    WorkerBuildContext,
    build_builtin_workers,
    worker_catalog,
)


class WorkerRegistryTests(unittest.TestCase):
    def test_builtin_specs_are_the_five_persona_workers(self) -> None:
        keys = [spec.key for spec in BUILTIN_WORKER_SPECS]

        self.assertEqual(
            keys,
            ["ReconWorker", "ArtifactWorker", "WebWorker", "ExploitWorker", "FlagWorker"],
        )
        self.assertEqual(len(keys), len(set(keys)))

    def test_build_builtin_workers_constructs_runtime_workers(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
            expected_flag="flag{ok}",
        )

        workers = build_builtin_workers(context)

        self.assertEqual([type(worker).__name__ for worker in workers], [spec.key for spec in BUILTIN_WORKER_SPECS])
        self.assertEqual(workers[-1].name, "flag-worker")
        self.assertEqual(getattr(workers[-1], "expected_flag"), "flag{ok}")

    def test_catalog_exposes_persona_group(self) -> None:
        catalog = worker_catalog()

        self.assertEqual(len(catalog), 5)
        self.assertEqual({item["group"] for item in catalog}, {"persona"})


if __name__ == "__main__":
    unittest.main()

