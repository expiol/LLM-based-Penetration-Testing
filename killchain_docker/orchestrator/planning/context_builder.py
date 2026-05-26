"""Build typed planner prompt context from RunState projections."""

from __future__ import annotations

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.rag.augmenter import RagAugmenter
from killchain_docker.orchestrator.planning.context_models import PlannerContext
from killchain_docker.orchestrator.planning.context_temperature import (
    compute_planner_temperature,
)
from killchain_docker.orchestrator.planning.stagnation_context import (
    build_stagnation_signals,
    pivot_summaries,
)
from killchain_docker.orchestrator.planning.techniques import technique_matrix_for
from killchain_docker.orchestrator.rag_policy import RagPolicy
from killchain_docker.orchestrator.todo_queue_reader import TodoQueueReader
from killchain_docker.prompt_projection import planner_todo as prompt_planner_todo
from killchain_docker.prompts.planner import build_planner_system_prompt
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.memory.projection import RunMemoryProjection
from killchain_docker.state.planner_projection import PlannerStateProjection
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.run_state import RunState


class PlannerContextBuilder:
    """Build the planner LLM context without reading RunState collections directly."""

    _MAX_TODOS = 40
    _MAX_ASSETS = 20
    _MAX_ARTIFACTS = 40
    _MAX_ENDPOINTS = 20
    _MAX_FINDINGS = 20
    _MAX_CREDENTIALS = 12
    _MAX_SESSIONS = 12
    _MAX_ROUNDS = 8
    _MAX_EXECUTION_LOG = 12
    _MAX_WORKING_MEMORY = 20

    def __init__(
        self,
        *,
        augmenter: RagAugmenter | None = None,
        evidence_builder: EvidenceContextBuilder | None = None,
    ) -> None:
        self.augmenter = augmenter or RagAugmenter.from_default()
        self.evidence_builder = evidence_builder or EvidenceContextBuilder()

    def build(self, state: RunState) -> PlannerContext:
        challenge_projection = ChallengeProjection(state)
        report_projection = RunReportProjection(state)
        planner_projection = PlannerStateProjection(state)
        category = challenge_projection.category()
        queue = TodoQueueReader(state)
        if self.augmenter is not None:
            self.augmenter.context_for(state)
        RagPolicy.annotate(state)
        return PlannerContext(
            objective=state.objective,
            authorized_scope=list(state.authorized_scope),
            challenge_category=category,
            planning_profiles=technique_matrix_for(category),
            state_summary=report_projection.summary(),
            assets=planner_projection.assets(limit=self._MAX_ASSETS),
            artifacts=planner_projection.artifacts(limit=self._MAX_ARTIFACTS),
            endpoints=planner_projection.endpoints(limit=self._MAX_ENDPOINTS),
            findings=planner_projection.findings(limit=self._MAX_FINDINGS),
            credentials=planner_projection.credentials(limit=self._MAX_CREDENTIALS),
            sessions=planner_projection.sessions(limit=self._MAX_SESSIONS),
            flag_candidates=planner_projection.flag_candidates(),
            rejected_flag_candidates=planner_projection.rejected_flag_candidates(),
            todos=[
                prompt_planner_todo(todo)
                for todo in queue.recent(limit=self._MAX_TODOS)
            ],
            recent_round_summaries=planner_projection.round_summaries(
                limit=self._MAX_ROUNDS
            ),
            recent_evidence_context=self.evidence_builder.build(state),
            recent_execution_log=planner_projection.execution_log(
                limit=self._MAX_EXECUTION_LOG
            ),
            run_memory=RunMemoryProjection(state).prompt_entries(
                limit=self._MAX_WORKING_MEMORY
            ),
            stagnation=build_stagnation_signals(state),
            near_miss_evidence=EvidenceProjectionStore(state).near_miss_summary(),
            pivot_summaries=pivot_summaries(state),
            knowledge_augmentation=planner_projection.rag_metadata(),
            open_todo_count=queue.open_count(),
            temperature=compute_planner_temperature(state),
        )

    def system_prompt(self, state: RunState) -> str:
        return build_planner_system_prompt(ChallengeProjection(state).category())
