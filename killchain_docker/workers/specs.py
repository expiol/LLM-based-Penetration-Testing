"""Shared worker registration primitives."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from killchain_docker.workers.base import WorkerAgent
from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient
from killchain_docker.tools import ExecutionPlane


@dataclass(frozen=True)
class WorkerBuildContext:
    """Dependencies required to construct runtime workers."""

    llm_client: LLMClient
    execution_plane: ExecutionPlane
    augmenter: KnowledgeAugmenter | None = None
    expected_flag: str | None = None


WorkerFactory = Callable[[WorkerBuildContext], WorkerAgent]


@dataclass(frozen=True)
class WorkerSpec:
    """Registration record for one worker class or factory."""

    key: str
    group: str
    factory: WorkerFactory
    description: str = ""

    def build(self, context: WorkerBuildContext) -> WorkerAgent:
        return self.factory(context)


def worker_spec(group: str, worker_cls: type[WorkerAgent]) -> WorkerSpec:
    """Create a standard capability-backed or LLM-backed worker spec."""

    def factory(context: WorkerBuildContext) -> WorkerAgent:
        return worker_cls(
            llm_client=context.llm_client,
            execution_plane=context.execution_plane,
        )

    return WorkerSpec(
        key=worker_cls.__name__,
        group=group,
        factory=factory,
        description=(worker_cls.__doc__ or "").strip().splitlines()[0] if worker_cls.__doc__ else "",
    )


def worker_specs(
    group: str,
    worker_classes: Iterable[type[WorkerAgent]],
) -> tuple[WorkerSpec, ...]:
    return tuple(worker_spec(group, worker_cls) for worker_cls in worker_classes)
