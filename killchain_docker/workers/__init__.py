"""Worker package and public persona registry exports."""

from typing import Any

from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.persona import (
    ArtifactWorker,
    ExploitWorker,
    FlagWorker,
    ReconWorker,
    WebWorker,
    WORKER_SPECS,
)
from killchain_docker.workers.protocols import Persona, PersonaSpec, ALL_PERSONAS
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.workers.worker import Worker

BUILTIN_WORKER_SPECS: tuple[WorkerSpec, ...] = WORKER_SPECS


def build_builtin_workers(context: WorkerBuildContext) -> list[WorkerAgent]:
    return [spec.build(context) for spec in BUILTIN_WORKER_SPECS]


def all_worker_classes() -> list[type]:
    return [ReconWorker, ArtifactWorker, WebWorker, ExploitWorker, FlagWorker]


def worker_catalog() -> list[dict[str, Any]]:
    return [
        {"key": spec.key, "group": spec.group, "description": spec.description}
        for spec in BUILTIN_WORKER_SPECS
    ]


__all__ = [
    "ALL_PERSONAS",
    "ArtifactWorker",
    "BUILTIN_WORKER_SPECS",
    "ExploitWorker",
    "FlagWorker",
    "Persona",
    "PersonaSpec",
    "ReconWorker",
    "WebWorker",
    "Worker",
    "WorkerAgent",
    "WorkerBuildContext",
    "WorkerSpec",
    "all_worker_classes",
    "build_builtin_workers",
    "worker_catalog",
]
