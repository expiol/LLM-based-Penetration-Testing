"""Shared worker registration primitives."""

from __future__ import annotations

from collections.abc import Callable
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
