"""LLM planner: thin pipeline orchestrator.

Combines :class:`BootstrapSeeder`, :class:`PlanStrategy`, :class:`TaskNormalizer`,
and :class:`TaskDeduper` into a single ``plan(state)`` call.

No filtering or capping happens here.  The LLM owns task selection and
stop_run.  The pipeline only:
- seeds initial tasks if there are none yet (BootstrapSeeder)
- asks the LLM for the next batch (PlanStrategy)
- normalizes input_context (TaskNormalizer)
- drops duplicates by dedupe_key (TaskDeduper)
"""

from __future__ import annotations

from nyuctf_mutil_killchain.llm import LLMClient
from nyuctf_mutil_killchain.orchestrator.planning.bootstrap import BootstrapSeeder
from nyuctf_mutil_killchain.orchestrator.planning.deduper import TaskDeduper
from nyuctf_mutil_killchain.orchestrator.planning.normalizer import TaskNormalizer
from nyuctf_mutil_killchain.orchestrator.planning.schemas import (
    PlannerDecision,
    TaskPlanner,
)
from nyuctf_mutil_killchain.orchestrator.planning.strategy import PlanStrategy
from nyuctf_mutil_killchain.state import GlobalState


class LLMPlanner(TaskPlanner):
    """LLM-driven planner with no soft-policy guards."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        bootstrap: BootstrapSeeder | None = None,
        strategy: PlanStrategy | None = None,
        normalizer: TaskNormalizer | None = None,
        deduper: TaskDeduper | None = None,
    ) -> None:
        self.bootstrap = bootstrap or BootstrapSeeder()
        self.strategy = strategy or PlanStrategy(llm_client)
        self.normalizer = normalizer or TaskNormalizer()
        self.deduper = deduper or TaskDeduper()

    def plan(self, state: GlobalState) -> PlannerDecision:
        bootstrap_decision = self.bootstrap.plan(state)
        llm_decision = self.strategy.propose(state)

        for task in llm_decision.tasks:
            self.normalizer.fill(task, state)
            task.metadata["planned_by"] = "llm-planner"

        existing_keys = {
            task.dedupe_key
            for task in bootstrap_decision.tasks
            if task.dedupe_key
        }
        deduped = self.deduper.merge(
            llm_decision.tasks,
            state,
            existing_keys=existing_keys,
        )

        merged_tasks = list(bootstrap_decision.tasks) + deduped
        return PlannerDecision(
            summary=llm_decision.summary or bootstrap_decision.summary,
            tasks=merged_tasks,
            notes=list(llm_decision.notes) + list(bootstrap_decision.notes),
            stop_run=llm_decision.stop_run,
        )
