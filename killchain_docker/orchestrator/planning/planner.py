"""PlannerAgent pipeline for high-level todo generation."""

from __future__ import annotations

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.orchestrator.planning.pipeline import PlanningPipeline
from killchain_docker.orchestrator.planning.schemas import PlannedTodo, PlannerAgent, PlannerDecision
from killchain_docker.orchestrator.planning.strategy import PlanStrategy
from killchain_docker.orchestrator.policy import CandidatePolicy
from killchain_docker.state import RunState, TodoPhase


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
        candidate_decision = self._candidate_validation_decision(state)
        if candidate_decision is not None:
            return candidate_decision

        llm_decision = self.strategy.propose(state)
        decision = self.pipeline.merge(state, llm_decision=llm_decision)
        if not self._needs_empty_plan_retry(state, decision, llm_decision):
            return decision

        retry_decision = self.strategy.propose(
            state,
            require_action=True,
            previous_summary=llm_decision.summary,
        )
        repaired = self.pipeline.merge(state, llm_decision=retry_decision)
        repaired.notes.extend(decision.notes)
        repaired.notes.append("Planner retried after empty non-terminal decision.")
        if repaired.todos or repaired.stop_run:
            return repaired
        fallback = self._continuation_decision(state, previous_summary=retry_decision.summary)
        if fallback is None:
            return repaired
        merged = self.pipeline.merge(state, llm_decision=fallback)
        merged.notes.extend(repaired.notes)
        merged.notes.append("Planner synthesized a grounded continuation after repeated empty plans.")
        return merged

    def _candidate_validation_decision(self, state: RunState) -> PlannerDecision | None:
        if not CandidatePolicy.validation_ready_candidates(state):
            return None
        decision = self.pipeline.merge(
            state,
            llm_decision=PlannerDecision(
                summary=(
                    "Grounded flag candidate is ready for deterministic validation."
                ),
                todos=[],
                notes=[
                    "Skipped LLM planning because flag validation is deterministic."
                ],
            ),
        )
        return decision if decision.todos else None

    @staticmethod
    def _needs_empty_plan_retry(
        state: RunState,
        decision: PlannerDecision,
        llm_decision: PlannerDecision,
    ) -> bool:
        if decision.todos or decision.stop_run:
            return False
        if state.solved or state.has_open_todos():
            return False
        if llm_decision.todos and not LLMPlanner._all_llm_todos_were_dropped(decision):
            return False
        return bool(state.todos or state.evidence or state.hypotheses)

    @staticmethod
    def _all_llm_todos_were_dropped(decision: PlannerDecision) -> bool:
        text = "\n".join(decision.notes).lower()
        return any(
            marker in text
            for marker in (
                "duplicate todo",
                "phase gate dropped",
                "scope gate dropped",
                "progress gate dropped",
            )
        )

    @staticmethod
    def _continuation_decision(
        state: RunState,
        *,
        previous_summary: str,
    ) -> PlannerDecision | None:
        if state.solved or state.has_open_todos():
            return None
        if not (state.todos or state.evidence or state.hypotheses or state.endpoints):
            return None

        evidence_ids = list(state.evidence.keys())[-3:]
        endpoint_ids = list(state.endpoints.keys())[-2:]
        hypothesis_ids = list(state.hypotheses.keys())[-2:]
        context = {
            "family": "execution-continuation",
            "novelty_key": f"continuation:{len(state.todos)}:{len(state.evidence)}",
        }
        if evidence_ids:
            context["evidence_ids"] = evidence_ids
        if endpoint_ids:
            context["endpoint_ids"] = endpoint_ids
        if hypothesis_ids:
            context["hypothesis_ids"] = hypothesis_ids

        phase = TodoPhase.EXPLOIT if (evidence_ids or endpoint_ids) else TodoPhase.ANALYSIS
        return PlannerDecision(
            summary="Synthesized continuation because repeated planner responses had no actionable todo.",
            todos=[
                PlannedTodo(
                    goal=(
                        "Continue from the latest grounded evidence and execute the next bounded "
                        "step toward recovering or validating a flag candidate. If execution is "
                        "blocked, produce a concise blocker diagnostic with the exact missing fact."
                    ),
                    phase=phase,
                    priority=80,
                    context=context,
                    success_criteria=[
                        "Use current-state evidence instead of repeating completed diagnostics.",
                        "Either recover a valid candidate or produce a precise blocker diagnostic.",
                    ],
                    constraints=[
                        "Stay within authorized scope.",
                        "Keep generated execution bounded and self-contained.",
                    ],
                    dedupe_key=f"planner:continuation:{len(state.todos)}:{len(state.evidence)}",
                )
            ],
            notes=[f"Previous empty planner summary: {previous_summary[:240]}"],
        )
