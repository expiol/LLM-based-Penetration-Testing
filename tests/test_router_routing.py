"""Tests for the LLM worker router (multi-candidate path)."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClientError, StaticLLMClient
from nyuctf_mutil_killchain.orchestrator.router import LLMWorkerRouter, WorkerRouteDecision
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport


class _StubWorker(WorkerAgent):
    """Minimal worker for routing tests."""

    def __init__(self, *, name: str, supported: tuple[str, ...]) -> None:
        super().__init__()
        self._name = name
        self._supported = supported

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str) -> None:
        self._name = value

    @property
    def supported_task_types(self) -> tuple[str, ...]:
        return self._supported

    def supports(self, task: Task) -> bool:
        return task.task_type in self._supported

    def can_route_task(self, task: Task, state: GlobalState):
        return self.supports(task), None

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        return WorkerReport(task_id=task.task_id, worker_name=self._name, success=True, summary="ok")


def _state() -> GlobalState:
    return GlobalState(
        objective="solve",
        authorized_scope=[],
        metadata={"challenge": {"category": "rev"}},
    )


class RouterTests(unittest.TestCase):
    def test_single_candidate_returns_without_calling_llm(self):
        router = LLMWorkerRouter(StaticLLMClient([]))
        worker = _StubWorker(name="only-worker", supported=("artifact.binary_triage",))
        task = Task(title="t", description="d", task_type="artifact.binary_triage")
        decision = router.route(task=task, state=_state(), candidates=[worker])
        self.assertEqual(decision.worker_name, "only-worker")
        self.assertEqual(decision.confidence, 1.0)

    def test_multi_candidate_calls_llm(self):
        candidates = [
            _StubWorker(name="binary", supported=("artifact.binary_triage",)),
            _StubWorker(name="deep-review", supported=("artifact.binary_triage",)),
        ]
        client = StaticLLMClient([
            {
                "worker_name": "deep-review",
                "rationale": "binary needs deeper analysis",
                "confidence": 0.9,
            }
        ])
        router = LLMWorkerRouter(client)
        task = Task(title="t", description="d", task_type="artifact.binary_triage")
        decision = router.route(task=task, state=_state(), candidates=candidates)
        self.assertEqual(decision.worker_name, "deep-review")
        self.assertGreater(decision.confidence, 0.5)

    def test_selected_worker_alias_accepted(self):
        candidates = [
            _StubWorker(name="binary", supported=("artifact.binary_triage",)),
            _StubWorker(name="deep-review", supported=("artifact.binary_triage",)),
        ]
        client = StaticLLMClient([
            {"selected_worker": "binary", "rationale": "binary triage first", "confidence": 0.85}
        ])
        router = LLMWorkerRouter(client)
        task = Task(title="t", description="d", task_type="artifact.binary_triage")
        decision = router.route(task=task, state=_state(), candidates=candidates)
        self.assertEqual(decision.worker_name, "binary")

    def test_invalid_choice_raises(self):
        candidates = [
            _StubWorker(name="binary", supported=("artifact.binary_triage",)),
            _StubWorker(name="deep-review", supported=("artifact.binary_triage",)),
        ]
        client = StaticLLMClient([
            {"worker_name": "imaginary", "rationale": "made up", "confidence": 0.5}
        ])
        router = LLMWorkerRouter(client)
        task = Task(title="t", description="d", task_type="artifact.binary_triage")
        with self.assertRaises(LLMClientError):
            router.route(task=task, state=_state(), candidates=candidates)


if __name__ == "__main__":
    unittest.main()
