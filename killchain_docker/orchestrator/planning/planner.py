"""PlannerAgent pipeline for high-level todo generation."""

from __future__ import annotations

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient
from killchain_docker.orchestrator.planning.bootstrap import BootstrapSeeder
from killchain_docker.orchestrator.planning.deduper import TaskDeduper
from killchain_docker.orchestrator.planning.normalizer import TaskNormalizer
from killchain_docker.orchestrator.planning.schemas import PlannerDecision, TaskPlanner
from killchain_docker.orchestrator.planning.strategy import PlanStrategy
from killchain_docker.state import RunState


class LLMPlanner(TaskPlanner):
    """PlannerAgent: observes the whole run and proposes small todo lists."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        bootstrap: BootstrapSeeder | None = None,
        strategy: PlanStrategy | None = None,
        normalizer: TaskNormalizer | None = None,
        deduper: TaskDeduper | None = None,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        self.bootstrap = bootstrap or BootstrapSeeder()
        self.strategy = strategy or PlanStrategy(llm_client, augmenter=augmenter)
        self.normalizer = normalizer or TaskNormalizer()
        self.deduper = deduper or TaskDeduper()

    def plan(self, state: RunState) -> PlannerDecision:
        bootstrap_decision = self.bootstrap.plan(state)
        llm_decision = self.strategy.propose(state)

        for todo in llm_decision.todos:
            self.normalizer.fill(todo, state)

        existing_keys = {
            todo.dedupe_key
            for todo in bootstrap_decision.todos
            if todo.dedupe_key
        }
        deduped = self.deduper.merge(
            llm_decision.todos,
            state,
            existing_keys=existing_keys,
        )
        merged = list(bootstrap_decision.todos) + deduped
        return PlannerDecision(
            summary=llm_decision.summary or bootstrap_decision.summary,
            todos=merged,
            notes=list(llm_decision.notes) + list(bootstrap_decision.notes),
            stop_run=llm_decision.stop_run,
        )

