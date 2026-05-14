"""PlannerAgent pipeline for high-level todo generation."""

from __future__ import annotations

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.bootstrap import BootstrapSeeder
from killchain_docker.orchestrator.planning.deduper import TodoDeduper
from killchain_docker.orchestrator.planning.normalizer import TodoNormalizer
from killchain_docker.orchestrator.planning.schemas import PlannerAgent, PlannedTodo, PlannerDecision
from killchain_docker.orchestrator.planning.strategy import PlanStrategy
from killchain_docker.state import RunState, TodoPhase, TodoStatus, todo_phase_rank


class LLMPlanner(PlannerAgent):
    """PlannerAgent: observes the whole run and proposes small todo lists."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        bootstrap: BootstrapSeeder | None = None,
        strategy: PlanStrategy | None = None,
        normalizer: TodoNormalizer | None = None,
        deduper: TodoDeduper | None = None,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        self.bootstrap = bootstrap or BootstrapSeeder()
        self.strategy = strategy or PlanStrategy(llm_client, augmenter=augmenter)
        self.normalizer = normalizer or TodoNormalizer()
        self.deduper = deduper or TodoDeduper()

    def plan(self, state: RunState) -> PlannerDecision:
        bootstrap_decision = self.bootstrap.plan(state)
        for todo in bootstrap_decision.todos:
            self.normalizer.fill(todo, state)
        try:
            llm_decision = self.strategy.propose(state)
        except LLMClientError as exc:
            todos, phase_notes = self._filter_to_frontier_phase(
                bootstrap_decision.todos,
                state,
            )
            return PlannerDecision(
                summary=bootstrap_decision.summary,
                todos=todos,
                notes=[
                    *bootstrap_decision.notes,
                    *phase_notes,
                    f"Planner LLM failed with {type(exc).__name__}: {exc}; using bootstrap todos only.",
                ],
                stop_run=False,
            )

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
        gated, phase_notes = self._filter_to_frontier_phase(merged, state)
        return PlannerDecision(
            summary=llm_decision.summary or bootstrap_decision.summary,
            todos=gated,
            notes=list(llm_decision.notes) + list(bootstrap_decision.notes) + phase_notes,
            stop_run=llm_decision.stop_run,
        )

    def _filter_to_frontier_phase(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        focus_phase = self._frontier_phase(todos, state)
        if focus_phase is None:
            return todos, []

        kept: list[PlannedTodo] = []
        phase_dropped: list[PlannedTodo] = []
        grounding_dropped: list[PlannedTodo] = []
        for todo in todos:
            if todo.phase != focus_phase:
                phase_dropped.append(todo)
                continue
            if not self._has_phase_grounding(todo, state):
                grounding_dropped.append(todo)
                continue
            kept.append(todo)

        notes: list[str] = []
        if phase_dropped:
            notes.append(
                "Planner phase gate kept "
                f"{focus_phase.value} todos and dropped {len(phase_dropped)} "
                f"todo(s) from other phases: {_todo_goal_preview(phase_dropped)}."
            )
        if grounding_dropped:
            notes.append(
                "Planner phase gate dropped "
                f"{len(grounding_dropped)} ungrounded {focus_phase.value} "
                f"todo(s): {_todo_goal_preview(grounding_dropped)}."
            )
        return kept, notes

    @staticmethod
    def _frontier_phase(todos: list[PlannedTodo], state: RunState) -> TodoPhase | None:
        open_phases = [
            todo.phase
            for todo in state.todos
            if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
        ]
        if open_phases:
            return min(open_phases, key=todo_phase_rank)
        if todos:
            return min((todo.phase for todo in todos), key=todo_phase_rank)
        return None

    @staticmethod
    def _has_phase_grounding(todo: PlannedTodo, state: RunState) -> bool:
        context = todo.context or {}
        if todo.phase == TodoPhase.EXPLOIT:
            return bool(
                state.findings
                or state.vulnerabilities
                or state.credentials
                or state.sessions
                or state.hypotheses
                or state.evidence
                or any(
                    context.get(key)
                    for key in (
                        "finding_id",
                        "finding_ids",
                        "vulnerability_id",
                        "vulnerability_ids",
                        "credential_id",
                        "credential_ids",
                        "session_id",
                        "session_ids",
                        "hypothesis_id",
                        "hypothesis_ids",
                        "evidence_id",
                        "evidence_ids",
                    )
                )
            )
        if todo.phase == TodoPhase.FLAG_VALIDATION:
            return bool(
                state.flag_candidates
                or context.get("candidate_flag")
                or context.get("flag_candidate_id")
                or context.get("flag_candidate_ids")
            )
        return True


def _todo_goal_preview(todos: list[PlannedTodo]) -> str:
    goals = [todo.goal[:80] for todo in todos[:5]]
    if len(todos) > 5:
        goals.append(f"+{len(todos) - 5} more")
    return "; ".join(goals)
