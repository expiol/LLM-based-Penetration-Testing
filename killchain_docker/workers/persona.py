"""Worker specs for the planner-router runtime.

Each persona is a frozen PersonaSpec data object. The WORKER_SPECS tuple
drives build_builtin_workers() — no intermediate subclasses needed.
"""

from __future__ import annotations

from killchain_docker.workers.protocols import (
    ARTIFACT_PERSONA,
    EXPLOIT_PERSONA,
    FLAG_PERSONA,
    RECON_PERSONA,
    WEB_PERSONA,
)
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.workers.worker import Worker


def _worker_factory(persona):
    """Return a factory closure that builds a Worker with the given persona."""
    def factory(ctx: WorkerBuildContext) -> Worker:
        return Worker(
            persona=persona,
            llm_client=ctx.llm_client,
            execution_plane=ctx.execution_plane,
        )
    return factory


def _flag_worker_factory(ctx: WorkerBuildContext) -> Worker:
    return Worker(
        persona=FLAG_PERSONA,
        llm_client=ctx.llm_client,
        execution_plane=ctx.execution_plane,
        expected_flag=ctx.expected_flag,
    )


WORKER_SPECS: tuple[WorkerSpec, ...] = (
    WorkerSpec("recon-worker", "persona", _worker_factory(RECON_PERSONA), RECON_PERSONA.routing_summary),
    WorkerSpec("artifact-worker", "persona", _worker_factory(ARTIFACT_PERSONA), ARTIFACT_PERSONA.routing_summary),
    WorkerSpec("web-worker", "persona", _worker_factory(WEB_PERSONA), WEB_PERSONA.routing_summary),
    WorkerSpec("exploit-worker", "persona", _worker_factory(EXPLOIT_PERSONA), EXPLOIT_PERSONA.routing_summary),
    WorkerSpec("flag-worker", "persona", _flag_worker_factory, FLAG_PERSONA.routing_summary),
)
