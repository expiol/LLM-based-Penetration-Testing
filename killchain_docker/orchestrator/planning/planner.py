"""PlannerAgent pipeline for high-level todo generation."""

from __future__ import annotations
from killchain_docker.rag.augmenter import RagAugmenter
from killchain_docker.llm.gateway import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.pipeline import PlanningPipeline
from killchain_docker.orchestrator.planning.schemas import (
    PlannedTodo,
    PlannerAgent,
    PlannerDecision,
)
from killchain_docker.orchestrator.planning.llm_strategy import LLMPlanningStrategy
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.run_state import RunState
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.planner_projection import PlannerStateProjection


class LLMPlanner(PlannerAgent):
    """PlannerAgent: observes the whole run and proposes small todo lists."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        strategy: LLMPlanningStrategy | None = None,
        pipeline: PlanningPipeline | None = None,
        augmenter: RagAugmenter | None = None,
    ) -> None:
        if llm_client is None:
            raise LLMClientError("LLMPlanner requires an LLM client.")
        self.pipeline = pipeline or PlanningPipeline()
        self.strategy = strategy or LLMPlanningStrategy(llm_client, augmenter=augmenter)

    def plan(self, state: RunState) -> PlannerDecision:
        candidate_decision = self._candidate_validation_decision(state)
        if candidate_decision is not None:
            return candidate_decision
        llm_decision = self.strategy.propose(state)
        decision = self.pipeline.merge(state, llm_decision=llm_decision)
        if not self._needs_empty_plan_retry(state, decision, llm_decision):
            return decision
        retry_decision = self.strategy.propose(
            state, require_action=True, previous_summary=llm_decision.summary
        )
        repaired = self.pipeline.merge(state, llm_decision=retry_decision)
        repaired.notes.extend(decision.notes)
        repaired.notes.append("Planner retried after empty non-terminal decision.")
        if repaired.todos or repaired.stop_run:
            return repaired
        fallback = self._continuation_decision(
            state, previous_summary=retry_decision.summary
        )
        if fallback is None:
            return repaired
        merged = self.pipeline.merge(state, llm_decision=fallback)
        merged.notes.extend(repaired.notes)
        merged.notes.append(
            "Planner synthesized a grounded continuation after repeated empty plans."
        )
        return merged

    def _candidate_validation_decision(self, state: RunState) -> PlannerDecision | None:
        if not CandidatePolicy.validation_ready_candidates(state):
            return None
        decision = self.pipeline.merge(
            state,
            llm_decision=PlannerDecision(
                summary="Grounded flag candidate is ready for deterministic validation.",
                todos=[],
                notes=[
                    "Skipped LLM planning because flag validation is deterministic."
                ],
            ),
        )
        return decision if decision.todos else None

    @staticmethod
    def _needs_empty_plan_retry(
        state: RunState, decision: PlannerDecision, llm_decision: PlannerDecision
    ) -> bool:
        if decision.todos or decision.stop_run:
            return False
        if RunOutcomeStore(state).is_solved or TodoQueue(state).has_open():
            return False
        if llm_decision.todos and (
            not LLMPlanner._all_llm_todos_were_dropped(decision)
        ):
            return False
        return PlannerStateProjection(state).empty_retry_available(
            todo_count=TodoQueue(state).count()
        )

    @staticmethod
    def _all_llm_todos_were_dropped(decision: PlannerDecision) -> bool:
        text = "\n".join(decision.notes).lower()
        return any(
            (
                marker in text
                for marker in (
                    "duplicate todo",
                    "dependency gate dropped",
                    "phase gate dropped",
                    "scope gate dropped",
                    "progress gate dropped",
                )
            )
        )

    @staticmethod
    def _continuation_decision(
        state: RunState, *, previous_summary: str
    ) -> PlannerDecision | None:
        queue = TodoQueue(state)
        todo_count = queue.count()
        if RunOutcomeStore(state).is_solved or queue.has_open():
            return None
        continuation = PlannerStateProjection(state).continuation(todo_count=todo_count)
        if continuation is None:
            return None
        return PlannerDecision(
            summary="Synthesized continuation because repeated planner responses had no actionable todo.",
            todos=[
                PlannedTodo(
                    goal="Continue from the latest grounded evidence and execute the next bounded step toward recovering or validating a flag candidate. If execution is blocked, produce a concise blocker diagnostic with the exact missing fact.",
                    phase=continuation.phase,
                    priority=80,
                    context=continuation.context,
                    success_criteria=[
                        "Use current-state evidence instead of repeating completed diagnostics.",
                        "Either recover a valid candidate or produce a precise blocker diagnostic.",
                    ],
                    constraints=[
                        "Stay within authorized scope.",
                        "Keep generated execution bounded and self-contained.",
                    ],
                    dedupe_key=continuation.dedupe_key,
                )
            ],
            notes=[f"Previous empty planner summary: {previous_summary[:240]}"],
        )
