"""LLM-driven high-level todo proposal."""

from __future__ import annotations

import json

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.prompts import get_planner_system_prompt, get_prompts
from killchain_docker.state import RunState, TodoStatus


class PlanStrategy:
    """Submit the current run state to the LLM and return high-level todos."""

    _MAX_TODOS = 40
    _MAX_FINDINGS = 20
    _MAX_ROUNDS = 8

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        if llm_client is None:
            raise LLMClientError("PlanStrategy requires an LLM client.")
        self.llm_client = llm_client
        self.augmenter = augmenter or KnowledgeAugmenter.from_default()

    def propose(self, state: RunState) -> PlannerDecision:
        return self.llm_client.generate_json(
            system_prompt=self._system_prompt(state),
            user_prompt=self._user_prompt(state),
            schema=PlannerDecision,
            temperature=0.2,
        )

    def _system_prompt(self, state: RunState) -> str:
        return get_planner_system_prompt(self._category(state))

    def _user_prompt(self, state: RunState) -> str:
        category = self._category(state)
        prompts = get_prompts(category)
        snapshot = {
            "objective": state.objective,
            "authorized_scope": state.authorized_scope,
            "challenge_category": category,
            "analysis_strategy": prompts.analysis_strategy,
            "exploit_strategy": prompts.exploit_strategy,
            "flag_recovery_hints": prompts.flag_recovery_hints,
            "summary": state.summary(),
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "kind": asset.kind,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "base_url": asset.base_url,
                    "services": [
                        {
                            "port": service.port,
                            "name": service.name,
                            "product": service.product,
                            "version": service.version,
                        }
                        for service in asset.services
                    ],
                    "tags": sorted(asset.tags),
                }
                for asset in state.assets.values()
            ],
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": (finding.description or "")[:360],
                    "metadata_preview": str(finding.metadata)[:360],
                }
                for finding in list(state.findings.values())[-self._MAX_FINDINGS:]
            ],
            "flag_candidates": [
                {
                    "candidate_id": candidate.candidate_id,
                    "value": candidate.value,
                    "source": candidate.source,
                    "validated": candidate.validated,
                }
                for candidate in list(state.flag_candidates.values())[-12:]
            ],
            "todos": self._serialize_todos(state),
            "recent_round_summaries": self._serialize_round_summaries(state),
            "recent_execution_log": [
                record.model_dump(mode="json")
                for record in state.execution_log[-20:]
            ],
        }
        related_writeups = self.augmenter.for_planner(state) if self.augmenter else []
        if related_writeups:
            snapshot["related_writeups"] = related_writeups
        snapshot["planning_contract"] = {
            "output": "Return PlannerDecision with todos, not worker names or tool names.",
            "todo_granularity": "Each todo is a high-level objective with context and success criteria.",
            "todo_phases": "Use exactly one phase per todo: recon, analysis, exploit, or flag_validation.",
            "single_phase_batch": (
                "All todos returned in one PlannerDecision must be in the same current phase. "
                "Do not mix recon/analysis/exploit/flag_validation in one batch."
            ),
            "dependency_rule": (
                "If a todo needs information produced by another proposed todo, do not return both. "
                "Return only the upstream todo now and wait for worker results before planning the dependent todo."
            ),
            "exploit_grounding": (
                "Only propose exploit-phase todos when the current state already contains grounded findings, "
                "vulnerabilities, credentials, sessions, hypotheses, evidence, or explicit ids in todo context."
            ),
            "stop_rule": "Set stop_run=true only when solved or genuinely exhausted.",
            "open_todos": self._open_todo_count(state),
        }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)

    @staticmethod
    def _category(state: RunState) -> str:
        return str(state.metadata.get("challenge", {}).get("category") or "misc").lower()

    def _serialize_todos(self, state: RunState) -> list[dict[str, object]]:
        return [
            {
                "todo_id": todo.todo_id,
                "goal": todo.goal,
                "phase": todo.phase,
                "status": todo.status,
                "priority": todo.priority,
                "context": todo.context,
                "result_summary": todo.result_summary[:300],
                "error": todo.error,
            }
            for todo in state.todos[-self._MAX_TODOS:]
        ]

    def _serialize_round_summaries(self, state: RunState) -> list[dict[str, object]]:
        return [
            round_record.summary.model_dump(mode="json")
            for round_record in list(getattr(state, "rounds", []) or [])[-self._MAX_ROUNDS:]
        ]

    @staticmethod
    def _open_todo_count(state: RunState) -> int:
        return sum(1 for todo in state.todos if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING})
