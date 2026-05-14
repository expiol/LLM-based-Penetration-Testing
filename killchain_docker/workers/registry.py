"""Built-in persona worker registry."""

from __future__ import annotations

from typing import Any

from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.persona import PERSONA_WORKERS, WORKER_SPECS
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec


BUILTIN_WORKER_SPECS: tuple[WorkerSpec, ...] = WORKER_SPECS


def build_builtin_workers(context: WorkerBuildContext) -> list[WorkerAgent]:
    """Instantiate the default persona worker set."""

    return [spec.build(context) for spec in BUILTIN_WORKER_SPECS]


def worker_catalog() -> list[dict[str, Any]]:
    """Return lightweight metadata for docs, diagnostics, or extension tooling."""

    return [
        {
            "key": spec.key,
            "group": spec.group,
            "description": spec.description,
        }
        for spec in BUILTIN_WORKER_SPECS
    ]


def all_worker_classes() -> list[type]:
    """Return every built-in persona worker class."""

    return list(PERSONA_WORKERS)

