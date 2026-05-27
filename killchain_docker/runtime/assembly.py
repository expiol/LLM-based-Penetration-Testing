"""Runtime assembly for planner, router, workers, and execution plane."""

from __future__ import annotations
from collections.abc import Callable
from pathlib import Path
from killchain_docker.intelligence.augmenter import IntelligenceAugmenter
from killchain_docker.intelligence.config import knowledge_mode
from killchain_docker.logging_utils import get_logger
from killchain_docker.llm.gateway import LLMClient, build_llm_client_from_env
from killchain_docker.memory.persistence import DurableMemoryStore
from killchain_docker.orchestrator.loop import Orchestrator
from killchain_docker.orchestrator.planning.planner import LLMPlanner
from killchain_docker.orchestrator.dispatch.router import RouterAgent
from killchain_docker.runtime.config import RunConfig
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.tools.registry import build_execution_plane
from killchain_docker.workers.personas.catalog import WorkerBuildContext, build_builtin_workers

LOGGER = get_logger(__name__)


def _resolve_memory_root(config: RunConfig) -> Path:
    if config.memory_root:
        return Path(config.memory_root)
    return Path(config.output_root) / "memory"


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
    resolved_knowledge_mode = knowledge_mode(config.knowledge_mode)
    memory_root = _resolve_memory_root(config)
    augmenter = IntelligenceAugmenter.from_default(
        mode=resolved_knowledge_mode,
        memory_root=memory_root,
        llm_client=llm_client,
    )
    metadata = dict(config.metadata)
    knowledge_meta = metadata.get("knowledge")
    metadata["knowledge"] = {
        **(knowledge_meta if isinstance(knowledge_meta, dict) else {}),
        "mode": resolved_knowledge_mode,
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
    memory_store = DurableMemoryStore(memory_root)
    challenge = ChallengeProjection(state)
    state.cross_run_memory = memory_store.load_relevant(
        category=challenge.category_raw() or None,
        challenge=challenge.name(),
    )
    worker_context = WorkerBuildContext(
        llm_client=llm_client,
        execution_plane=execution_plane,
        expected_flag=expected_flag,
    )
    orchestrator = Orchestrator(
        state=state,
        workers=build_builtin_workers(worker_context),
        planner=planner,
        router=router,
        emit=emit,
        checkpoint_callback=checkpoint_callback,
        durable_memory_store=memory_store,
    )
    return (state, orchestrator, llm_client)

