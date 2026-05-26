"""Runtime assembly for planner, router, workers, and execution plane."""

from __future__ import annotations
from collections.abc import Callable
from killchain_docker.knowledge.augmenter import KnowledgeAugmenter
from killchain_docker.knowledge.retriever import rag_mode
from killchain_docker.logging_utils import get_logger
from killchain_docker.llm.gateway import LLMClient, build_llm_client_from_env
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning.planner import LLMPlanner
from killchain_docker.orchestrator.router import RouterAgent
from killchain_docker.runtime.config import RunConfig
from killchain_docker.state.run_state import RunState
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.tools.registry import build_execution_plane
from killchain_docker.workers.catalog import WorkerBuildContext, build_builtin_workers

LOGGER = get_logger(__name__)


def build_runtime(
    config: RunConfig,
    *,
    recorder: object | None = None,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
    llm_client: LLMClient | None = None,
    checkpoint_callback: Callable[[RunState], None] | None = None,
) -> tuple[RunState, Orchestrator, LLMClient]:
    """Assemble state, planner, workers, and execution plane for one run."""
    if llm_client is None:
        llm_client = build_llm_client_from_env()
    resolved_rag_mode = rag_mode(config.rag_mode)
    augmenter = KnowledgeAugmenter.from_default(mode=resolved_rag_mode)
    metadata = dict(config.metadata)
    rag_metadata = metadata.get("rag")
    metadata["rag"] = {
        **(rag_metadata if isinstance(rag_metadata, dict) else {}),
        "mode": resolved_rag_mode,
    }
    planner = LLMPlanner(llm_client, augmenter=augmenter)
    router = RouterAgent(llm_client)
    emit = recorder.emit if recorder is not None else LOGGER.info
    execution_plane = execution_plane or build_execution_plane()
    state = RunState(
        objective=config.objective,
        authorized_scope=config.authorized_scope,
        metadata=metadata,
    )
    worker_context = WorkerBuildContext(
        llm_client=llm_client,
        execution_plane=execution_plane,
        augmenter=augmenter,
        expected_flag=expected_flag,
    )
    orchestrator = Orchestrator(
        state=state,
        workers=build_builtin_workers(worker_context),
        planner=planner,
        router=router,
        emit=emit,
        checkpoint_callback=checkpoint_callback,
    )
    return (state, orchestrator, llm_client)
