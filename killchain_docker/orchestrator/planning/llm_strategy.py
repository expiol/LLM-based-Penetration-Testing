"""LLM-backed planner decision generation."""

from __future__ import annotations

from killchain_docker.knowledge.augmenter import KnowledgeAugmenter
from killchain_docker.llm.gateway import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.context_builder import PlannerContextBuilder
from killchain_docker.orchestrator.planning.prompt_renderer import render_planner_prompt
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.orchestrator.planning.source_sanitizer import (
    sanitize_planner_decision,
)
from killchain_docker.state.run_state import RunState


class LLMPlanningStrategy:
    """Submit typed planner context to the LLM and sanitize the decision."""

    def __init__(
        self, llm_client: LLMClient, *, augmenter: KnowledgeAugmenter | None = None
    ) -> None:
        if llm_client is None:
            raise LLMClientError("LLMPlanningStrategy requires an LLM client.")
        self.llm_client = llm_client
        self.context_builder = PlannerContextBuilder(augmenter=augmenter)

    def propose(
        self,
        state: RunState,
        *,
        require_action: bool = False,
        previous_summary: str | None = None,
    ) -> PlannerDecision:
        ctx = self.context_builder.build(state)
        decision = self.llm_client.generate_json(
            system_prompt=self.context_builder.system_prompt(state),
            user_prompt=render_planner_prompt(
                ctx,
                require_action=require_action,
                previous_summary=previous_summary,
            ),
            schema=PlannerDecision,
            temperature=ctx.temperature,
        )
        return sanitize_planner_decision(decision)
