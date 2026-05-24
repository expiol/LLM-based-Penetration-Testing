"""PlannerContextBuilder: typed, inspectable context for the LLM planner.

Extracts the 150+ lines of snapshot construction from PlanStrategy.propose()
into a standalone builder with a typed PlannerContext output. Tests can assert
on individual fields without mocking the LLM or parsing prompt strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.orchestrator.policy import ProgressPolicy, RagPolicy, TodoPolicy
from killchain_docker.orchestrator.planning.techniques import technique_matrix_for
from killchain_docker.prompt_projection import (
    artifacts as prompt_artifacts,
    execution_record as prompt_execution_record,
    planner_todo as prompt_planner_todo,
    working_memory as prompt_working_memory,
)
from killchain_docker.prompt_bounds import bounded_value, trim_text
from killchain_docker.prompts import get_planner_system_prompt
from killchain_docker.state import RunState, TodoStatus


@dataclass
class StagnationInfo:
    """Structured stagnation signals for the planner."""

    flag_candidates_seen: int = 0
    rounds_without_flag_candidate: int = 0
    progress_policy: dict[str, Any] = field(default_factory=dict)
    family_attempt_counts: dict[str, int] = field(default_factory=dict)
    cooldown_families: list[str] = field(default_factory=list)
    escalation_required: str | None = None
    forced_pivot: dict[str, Any] | None = None
    recent_script_no_candidate_count: int = 0


@dataclass
class PlannerContext:
    """Typed context for the planner LLM call.

    Each field is independently inspectable and testable.
    """

    # Core objective
    objective: str = ""
    authorized_scope: list[str] = field(default_factory=list)
    challenge_category: str = "misc"

    # Strategy context
    planning_profiles: list[dict[str, object]] = field(default_factory=list)

    # State snapshot
    state_summary: dict[str, Any] = field(default_factory=dict)
    assets: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    flag_candidates: list[dict[str, Any]] = field(default_factory=list)
    rejected_flag_candidates: list[dict[str, Any]] = field(default_factory=list)
    todos: list[dict[str, Any]] = field(default_factory=list)

    # Evidence
    recent_round_summaries: list[dict[str, Any]] = field(default_factory=list)
    recent_evidence_context: list[dict[str, Any]] = field(default_factory=list)
    recent_execution_log: list[dict[str, Any]] = field(default_factory=list)
    working_memory: dict[str, str] = field(default_factory=dict)

    # Stagnation
    stagnation: dict[str, Any] = field(default_factory=dict)
    near_miss_evidence: list[dict[str, Any]] = field(default_factory=list)
    pivot_summaries: list[dict[str, Any]] = field(default_factory=list)

    # Knowledge augmentation
    knowledge_augmentation: dict[str, Any] = field(default_factory=dict)
    related_writeups: list[dict[str, Any]] = field(default_factory=list)
    related_writeups_warning: str | None = None

    # Computed
    open_todo_count: int = 0
    temperature: float = 0.2


class PlannerContextBuilder:
    """Builds a typed PlannerContext from RunState.

    Replaces the inlined snapshot construction in PlanStrategy._user_prompt().
    """

    _MAX_TODOS = 40
    _MAX_ASSETS = 20
    _MAX_ARTIFACTS = 40
    _MAX_ENDPOINTS = 20
    _MAX_FINDINGS = 20
    _MAX_ROUNDS = 8
    _MAX_EXECUTION_LOG = 12
    _MAX_WORKING_MEMORY = 20

    def __init__(
        self,
        *,
        augmenter: KnowledgeAugmenter | None = None,
        evidence_builder: EvidenceContextBuilder | None = None,
    ) -> None:
        self.augmenter = augmenter or KnowledgeAugmenter.from_default()
        self.evidence_builder = evidence_builder or EvidenceContextBuilder()

    def build(self, state: RunState) -> PlannerContext:
        category = self._category(state)
        stagnation = self._build_stagnation(state)

        if self.augmenter is not None:
            self.augmenter.context_for(state)
        RagPolicy.annotate(state)
        rag_meta = state.metadata.get("rag")
        knowledge_augmentation = self._planner_knowledge_metadata(rag_meta)

        return PlannerContext(
            objective=state.objective,
            authorized_scope=list(state.authorized_scope),
            challenge_category=category,
            planning_profiles=technique_matrix_for(category),
            state_summary=state.summary(),
            assets=self._serialize_assets(state),
            artifacts=prompt_artifacts(state, limit=self._MAX_ARTIFACTS),
            endpoints=self._serialize_endpoints(state),
            findings=self._serialize_findings(state),
            flag_candidates=self._serialize_flag_candidates(state),
            rejected_flag_candidates=self._serialize_rejected_flag_candidates(state),
            todos=[
                prompt_planner_todo(todo)
                for todo in state.todos[-self._MAX_TODOS:]
            ],
            recent_round_summaries=self._serialize_round_summaries(state),
            recent_evidence_context=self.evidence_builder.build(state),
            recent_execution_log=[
                prompt_execution_record(record)
                for record in state.execution_log[-self._MAX_EXECUTION_LOG:]
            ],
            working_memory=prompt_working_memory(state, limit=self._MAX_WORKING_MEMORY),
            stagnation=stagnation,
            near_miss_evidence=self._near_miss_evidence(state),
            pivot_summaries=self._pivot_summaries(state),
            knowledge_augmentation=dict(knowledge_augmentation),
            open_todo_count=self._open_todo_count(state),
            temperature=self._compute_temperature(state),
        )

    def system_prompt(self, state: RunState) -> str:
        return get_planner_system_prompt(self._category(state))

    # ------------------------------------------------------------------
    # Private helpers (moved from PlanStrategy)
    # ------------------------------------------------------------------

    @staticmethod
    def _planner_knowledge_metadata(raw: object) -> dict[str, Any]:
        """Return planner-useful RAG context without provenance labels."""
        if not isinstance(raw, dict):
            return {}
        allowed = {
            "enabled",
            "status",
            "hit_count",
            "hint_count",
            "policy",
            "stalled_families",
        }
        metadata = {key: raw[key] for key in allowed if key in raw}
        hints = raw.get("knowledge_hints")
        if isinstance(hints, list):
            metadata["knowledge_hints"] = [
                hint for hint in hints
                if isinstance(hint, dict)
            ][:3]
        if "hint_count" not in metadata and isinstance(hints, list):
            metadata["hint_count"] = sum(1 for item in hints if isinstance(item, dict))
        return metadata

    @staticmethod
    def _category(state: RunState) -> str:
        return str(state.metadata.get("challenge", {}).get("category") or "misc").lower()

    @staticmethod
    def _compute_temperature(state: RunState) -> float:
        snapshot = ProgressPolicy.stagnation_snapshot(state)
        cooldown_count = len(snapshot.get("cooldown_families", []))
        rounds_without_flag = len(state.rounds) if not state.flag_candidates else 0
        if cooldown_count >= 2 or rounds_without_flag >= 8:
            return 0.6
        if cooldown_count >= 1 or rounds_without_flag >= 5:
            return 0.4
        return 0.2

    @staticmethod
    def _open_todo_count(state: RunState) -> int:
        return sum(1 for todo in state.todos if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING})

    @staticmethod
    def _serialize_assets(state: RunState) -> list[dict[str, Any]]:
        return [
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
            for asset in list(state.assets.values())[-PlannerContextBuilder._MAX_ASSETS:]
        ]

    @staticmethod
    def _serialize_endpoints(state: RunState) -> list[dict[str, Any]]:
        return [
            {
                "endpoint_id": endpoint.endpoint_id,
                "asset_ref": endpoint.asset_ref,
                "url": endpoint.url,
                "hostname": endpoint.hostname,
                "port": endpoint.port,
                "protocol": endpoint.protocol,
                "status_code": endpoint.status_code,
                "title": endpoint.title,
                "metadata_preview": str(endpoint.metadata)[:360],
            }
            for endpoint in list(state.endpoints.values())[-PlannerContextBuilder._MAX_ENDPOINTS:]
        ]

    def _serialize_findings(self, state: RunState) -> list[dict[str, Any]]:
        return [
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "description": (finding.description or "")[:360],
                "metadata_preview": str(finding.metadata)[:360],
            }
            for finding in list(state.findings.values())[-self._MAX_FINDINGS:]
        ]

    @staticmethod
    def _serialize_flag_candidates(state: RunState) -> list[dict[str, Any]]:
        return [
            {
                "candidate_id": candidate.candidate_id,
                "value": candidate.value,
                "source": candidate.source,
                "validated": candidate.validated,
            }
            for candidate in list(state.flag_candidates.values())[-12:]
        ]

    @staticmethod
    def _serialize_rejected_flag_candidates(state: RunState) -> list[dict[str, Any]]:
        return [
            {
                "value": item.value[:220],
                "reason": item.reason,
                "source": item.source,
                "evidence_refs": item.evidence_refs[-4:],
            }
            for item in state.rejected_flag_candidates[-16:]
        ]

    def _serialize_round_summaries(self, state: RunState) -> list[dict[str, Any]]:
        return [
            bounded_value(
                round_record.summary.model_dump(mode="json"),
                width=500,
                list_limit=8,
                dict_limit=10,
            )
            for round_record in list(getattr(state, "rounds", []) or [])[-self._MAX_ROUNDS:]
        ]

    @staticmethod
    def _build_stagnation(state: RunState) -> dict[str, Any]:
        snapshot = ProgressPolicy.stagnation_snapshot(state)
        cooldown_families = snapshot.get("cooldown_families", [])

        # Family counts and examples
        family_counts: dict[str, int] = {}
        family_examples: dict[str, list[str]] = {}
        todo_status_counts: dict[str, int] = {}
        for todo in state.todos:
            status = str(todo.status)
            todo_status_counts[status] = todo_status_counts.get(status, 0) + 1
            family = TodoPolicy.family_for(todo.goal, todo.context)
            family_counts[family] = family_counts.get(family, 0) + 1
            family_examples.setdefault(family, [])
            if len(family_examples[family]) < 3:
                family_examples[family].append(todo.goal[:120])

        recent_records = state.execution_log[-20:]
        recent_no_candidate_scripts = [
            {
                "task_id": record.task_id,
                "worker_name": record.worker_name,
                "summary": record.summary[:240],
                "error": (record.error or "")[:160],
            }
            for record in recent_records
            if "script execution" in record.summary.lower()
            and "0 flag candidate" in record.summary.lower()
        ]

        repeated_families = [
            {"family": family, "count": count, "examples": family_examples.get(family, [])}
            for family, count in sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))
            if count > 1 and family != "other"
        ][:6]

        signals: dict[str, Any] = {
            "flag_candidates_seen": len(state.flag_candidates),
            "rounds_without_flag_candidate": len(state.rounds) if not state.flag_candidates else 0,
            "progress_policy": snapshot,
            "family_attempt_counts": dict(family_counts),
            "recent_script_no_candidate_count": len(recent_no_candidate_scripts),
            "recent_script_no_candidate_results": recent_no_candidate_scripts[-6:],
            "todo_status_counts": todo_status_counts,
            "partial_todos": [
                {
                    "todo_id": todo.todo_id,
                    "goal": todo.goal[:160],
                    "result_summary": todo.result_summary[:240],
                    "partial_reason": (todo.error or "")[:160],
                }
                for todo in state.todos[-20:]
                if str(todo.status) == "partial"
            ],
            "failed_todos": [
                {"todo_id": todo.todo_id, "goal": todo.goal[:160], "error": (todo.error or "")[:180]}
                for todo in state.todos[-20:]
                if str(todo.status) == "failed"
            ],
            "open_todos": [
                {"todo_id": todo.todo_id, "phase": str(todo.phase), "goal": todo.goal[:160], "attempts": todo.attempts}
                for todo in state.todos[-20:]
                if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
            ],
            "repeated_todo_families": repeated_families,
            "guidance": (
                "These signals are PRESCRIPTIVE. If escalation_required or forced_pivot is present, "
                "you MUST comply: either set stop_run=true or propose a fundamentally different "
                "attack vector that does NOT belong to any banned family. "
                "Rephrasing the same strategy will be rejected by the pipeline."
            ),
        }

        if cooldown_families:
            top = cooldown_families[0]
            count = family_counts.get(top, 0)
            signals["escalation_required"] = (
                f"Family {top!r} is in cooldown after {count} attempts. "
                "You MUST propose a fundamentally different approach "
                "(different algorithm, different tool, different attack vector). "
                "Do NOT rephrase the same strategy."
            )

        forced_pivot = state.metadata.get("forced_pivot")
        if isinstance(forced_pivot, dict):
            signals["forced_pivot"] = forced_pivot

        return signals

    @staticmethod
    def _near_miss_evidence(state: RunState) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for evidence_id, evidence in list(state.evidence.items())[-20:]:
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context") or {}
            near_misses = list(ctx.get("near_miss_candidates") or [])
            if not near_misses:
                continue
            out.append({
                "evidence_id": evidence_id,
                "tool_name": evidence.tool_name,
                "near_miss_candidates": near_misses[:3],
                "stdout_tail": str(ctx.get("stdout", ""))[-400:],
            })
        return out

    @staticmethod
    def _pivot_summaries(state: RunState) -> list[dict[str, Any]]:
        seen_families: set[str] = set()
        summaries: list[dict[str, Any]] = []
        for todo in state.todos:
            family = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
            if family in seen_families:
                continue
            consecutive = ProgressPolicy._consecutive_failures_without_evidence(state, family)
            if consecutive < ProgressPolicy.CONSECUTIVE_FAILURE_CAP:
                continue
            seen_families.add(family)
            family_todos = [
                t for t in state.todos
                if str(t.context.get("family") or TodoPolicy.family_for(t.goal, t.context)) == family
            ]
            summaries.append({
                "family": family,
                "total_attempts": len(family_todos),
                "approaches_tried": [
                    {"goal": t.goal[:200], "error": (t.error or "")[:200], "status": str(t.status)}
                    for t in family_todos[-5:]
                ],
                "pivot_instruction": (
                    f"Family '{family}' is bankrupt after {consecutive} consecutive failures. "
                    "You MUST try a fundamentally different approach: different algorithm, "
                    "different tool, different attack surface. Do NOT rephrase previous attempts."
                ),
            })
        return summaries


__all__ = [
    "PlannerContext",
    "PlannerContextBuilder",
    "StagnationInfo",
]
