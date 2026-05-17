"""Worker package and public persona registry exports."""

from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.persona import WORKER_SPECS
from killchain_docker.workers.protocols import Persona, PersonaSpec, ALL_PERSONAS
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.workers.worker import Worker

BUILTIN_WORKER_SPECS: tuple[WorkerSpec, ...] = WORKER_SPECS


def build_builtin_workers(context: WorkerBuildContext) -> list[WorkerAgent]:
    return [spec.build(context) for spec in BUILTIN_WORKER_SPECS]


__all__ = [
    "ALL_PERSONAS",
    "BUILTIN_WORKER_SPECS",
    "Persona",
    "PersonaSpec",
    "Worker",
    "WorkerAgent",
    "WorkerBuildContext",
    "WorkerSpec",
    "build_builtin_workers",
]
