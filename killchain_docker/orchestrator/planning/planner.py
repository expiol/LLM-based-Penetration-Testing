"""PlannerAgent pipeline for high-level todo generation."""

from __future__ import annotations

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.orchestrator.planning.pipeline import PlanningPipeline
from killchain_docker.orchestrator.planning.schemas import PlannerAgent, PlannerDecision
from killchain_docker.orchestrator.planning.strategy import PlanStrategy
from killchain_docker.state import RunState


class LLMPlanner(PlannerAgent):
    """PlannerAgent: observes the whole run and proposes small todo lists."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        strategy: PlanStrategy | None = None,
        pipeline: PlanningPipeline | None = None,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        if llm_client is None:
            raise LLMClientError("LLMPlanner requires an LLM client.")
        self.pipeline = pipeline or PlanningPipeline()
        self.strategy = strategy or PlanStrategy(llm_client, augmenter=augmenter)

    def plan(self, state: RunState) -> PlannerDecision:
        llm_decision = self.strategy.propose(state)
        return self.pipeline.merge(state, llm_decision=llm_decision)
