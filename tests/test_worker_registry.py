"""Tests for the persona worker registry."""

from __future__ import annotations
import unittest
from killchain_docker.llm.gateway import StaticLLMClient
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase
from killchain_docker.workers.catalog import (
    ALL_PERSONAS,
    WorkerBuildContext,
    build_builtin_workers,
)


class WorkerRegistryTests(unittest.TestCase):
    def test_persona_catalog_has_the_five_runtime_workers(self) -> None:
        names = [persona.name for persona in ALL_PERSONAS]
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
        self.assertEqual(len(names), len(set(names)))

    def test_build_builtin_workers_constructs_runtime_workers(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
            expected_flag="flag{ok}",
        )
        workers = build_builtin_workers(context)
        self.assertEqual(
            [worker.name for worker in workers],
            [persona.name for persona in ALL_PERSONAS],
        )
        self.assertEqual(workers[-1].name, "flag-worker")
        self.assertEqual(getattr(workers[-1], "expected_flag"), "flag{ok}")

    def test_real_flag_worker_eligibility_uses_flag_validation_phase(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]),
            execution_plane=ExecutionPlane(),
            expected_flag="flag{ok}",
        )
        workers = {worker.name: worker for worker in build_builtin_workers(context)}
        allowed, reason = workers["flag-worker"].can_route_task(
            TodoItem(goal="Validate candidate.", phase=TodoPhase.FLAG_VALIDATION),
            RunState(objective="Solve."),
        )
        self.assertTrue(allowed, reason)

    def test_worker_eligibility_honors_required_capability(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]), execution_plane=ExecutionPlane()
        )
        workers = {worker.name: worker for worker in build_builtin_workers(context)}
        allowed, reason = workers["web-worker"].can_route_task(
            TodoItem(
                goal="Inspect the binary.",
                context={"dispatch_intent": {"required_capability": "gdb"}},
            ),
            RunState(objective="Solve."),
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "missing required capability: gdb")

    def test_worker_eligibility_honors_excluded_workers(self) -> None:
        context = WorkerBuildContext(
            llm_client=StaticLLMClient([]), execution_plane=ExecutionPlane()
        )
        workers = {worker.name: worker for worker in build_builtin_workers(context)}
        allowed, reason = workers["artifact-worker"].can_route_task(
            TodoItem(
                goal="Inspect file.", context={"exclude_workers": ["artifact-worker"]}
            ),
            RunState(objective="Solve."),
        )
        self.assertFalse(allowed)
        self.assertEqual(reason, "worker explicitly excluded by task metadata")


if __name__ == "__main__":
    unittest.main()
