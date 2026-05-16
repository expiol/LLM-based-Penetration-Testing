"""High-level persona workers for the planner-router runtime.

This module now delegates to the unified Worker class with PersonaSpec injection.
The legacy class names are preserved as thin aliases for backward compatibility.
"""

from __future__ import annotations

from killchain_docker.llm import LLMClient
from killchain_docker.workers.protocols import (
    ARTIFACT_PERSONA,
    EXPLOIT_PERSONA,
    FLAG_PERSONA,
    RECON_PERSONA,
    WEB_PERSONA,
)
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.workers.worker import Worker


# Backward-compatible class aliases
class ReconWorker(Worker):
    name = RECON_PERSONA.name
    routing_summary = RECON_PERSONA.routing_summary
    allowed_capabilities = RECON_PERSONA.allowed_capabilities

    def __init__(self, *, llm_client=None, execution_plane=None, tool_gateway=None):
        super().__init__(persona=RECON_PERSONA, llm_client=llm_client, execution_plane=execution_plane, tool_gateway=tool_gateway)


class ArtifactWorker(Worker):
    name = ARTIFACT_PERSONA.name
    routing_summary = ARTIFACT_PERSONA.routing_summary
    allowed_capabilities = ARTIFACT_PERSONA.allowed_capabilities

    def __init__(self, *, llm_client=None, execution_plane=None, tool_gateway=None):
        super().__init__(persona=ARTIFACT_PERSONA, llm_client=llm_client, execution_plane=execution_plane, tool_gateway=tool_gateway)


class WebWorker(Worker):
    name = WEB_PERSONA.name
    routing_summary = WEB_PERSONA.routing_summary
    allowed_capabilities = WEB_PERSONA.allowed_capabilities

    def __init__(self, *, llm_client=None, execution_plane=None, tool_gateway=None):
        super().__init__(persona=WEB_PERSONA, llm_client=llm_client, execution_plane=execution_plane, tool_gateway=tool_gateway)


class ExploitWorker(Worker):
    name = EXPLOIT_PERSONA.name
    routing_summary = EXPLOIT_PERSONA.routing_summary
    allowed_capabilities = EXPLOIT_PERSONA.allowed_capabilities

    def __init__(self, *, llm_client=None, execution_plane=None, tool_gateway=None):
        super().__init__(persona=EXPLOIT_PERSONA, llm_client=llm_client, execution_plane=execution_plane, tool_gateway=tool_gateway)


class FlagWorker(Worker):
    name = FLAG_PERSONA.name
    routing_summary = FLAG_PERSONA.routing_summary
    allowed_capabilities = FLAG_PERSONA.allowed_capabilities

    def __init__(self, *, llm_client=None, execution_plane=None, tool_gateway=None, expected_flag=None):
        super().__init__(persona=FLAG_PERSONA, llm_client=llm_client, execution_plane=execution_plane, tool_gateway=tool_gateway, expected_flag=expected_flag)


def _flag_factory(context: WorkerBuildContext) -> FlagWorker:
    return FlagWorker(
        llm_client=context.llm_client,
        execution_plane=context.execution_plane,
        expected_flag=context.expected_flag,
    )


WORKER_SPECS: tuple[WorkerSpec, ...] = (
    WorkerSpec("ReconWorker", "persona", lambda ctx: ReconWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), ReconWorker.routing_summary.fget(None) if False else RECON_PERSONA.routing_summary),
    WorkerSpec("ArtifactWorker", "persona", lambda ctx: ArtifactWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), ARTIFACT_PERSONA.routing_summary),
    WorkerSpec("WebWorker", "persona", lambda ctx: WebWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), WEB_PERSONA.routing_summary),
    WorkerSpec("ExploitWorker", "persona", lambda ctx: ExploitWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), EXPLOIT_PERSONA.routing_summary),
    WorkerSpec("FlagWorker", "persona", _flag_factory, FLAG_PERSONA.routing_summary),
)
