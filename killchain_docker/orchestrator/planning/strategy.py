"""LLM-driven high-level todo proposal."""

from __future__ import annotations

import json

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.orchestrator.policy import ProgressPolicy, RagPolicy
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
        self.evidence_context = EvidenceContextBuilder()

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
            "recent_evidence_context": self.evidence_context.build(state),
            "recent_execution_log": [
                record.model_dump(mode="json")
                for record in state.execution_log[-20:]
            ],
            "stagnation_signals": self._stagnation_signals(state),
        }
        RagPolicy.annotate(state)
        related_writeups = self.augmenter.for_planner(state) if self.augmenter else []
        if related_writeups:
            snapshot["related_writeups"] = related_writeups
            rag_meta = state.metadata.get("rag")
            if isinstance(rag_meta, dict) and rag_meta.get("policy") == "possibly_misleading":
                snapshot["related_writeups_warning"] = (
                    "Prior attempts informed by these writeups have stalled in "
                    f"{rag_meta.get('stalled_families', [])}. Treat the writeups as "
                    "hints, not ground truth; consider alternative ciphers/algorithms."
                )
        snapshot["planning_contract"] = {
            "output": "Return PlannerDecision with todos, not worker names or tool names.",
            "todo_granularity": "Each todo is a high-level objective with context and success criteria.",
            "todo_phases": "Use exactly one phase per todo: recon, analysis, exploit, or flag_validation.",
            "phase_semantics": (
                "Use flag_validation only for concrete flag candidates already present in state or todo context. "
                "Deriving, decrypting, extracting, or recovering a candidate flag is analysis unless it runs a grounded exploit."
            ),
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
            "evidence_context_rule": (
                "Use recent_evidence_context as grounded facts from completed tools. "
                "Do not re-request hexdumps, stdout, binary traits, or disassembly snippets "
                "that are already present there; plan the next distinct step from that evidence. "
                "Do not plan work that depends on /tmp files written by an earlier todo. "
                "If raw data is needed, use recent_evidence_context or regenerate and print it in the same script."
            ),
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

    def _stagnation_signals(self, state: RunState) -> dict[str, object]:
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
        todo_status_counts: dict[str, int] = {}
        family_counts: dict[str, int] = {}
        family_examples: dict[str, list[str]] = {}
        for todo in state.todos:
            status = str(todo.status)
            todo_status_counts[status] = todo_status_counts.get(status, 0) + 1
            family = self._todo_family(todo.goal)
            family_counts[family] = family_counts.get(family, 0) + 1
            family_examples.setdefault(family, [])
            if len(family_examples[family]) < 3:
                family_examples[family].append(todo.goal[:120])

        repeated_families = [
            {
                "family": family,
                "count": count,
                "examples": family_examples.get(family, []),
            }
            for family, count in sorted(family_counts.items(), key=lambda item: (-item[1], item[0]))
            if count > 1 and family != "other"
        ][:6]

        return {
            "flag_candidates_seen": len(state.flag_candidates),
            "rounds_without_flag_candidate": len(state.rounds) if not state.flag_candidates else 0,
            "progress_policy": ProgressPolicy.stagnation_snapshot(state),
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
                {
                    "todo_id": todo.todo_id,
                    "goal": todo.goal[:160],
                    "error": (todo.error or "")[:180],
                }
                for todo in state.todos[-20:]
                if str(todo.status) == "failed"
            ],
            "open_todos": [
                {
                    "todo_id": todo.todo_id,
                    "phase": str(todo.phase),
                    "goal": todo.goal[:160],
                    "attempts": todo.attempts,
                }
                for todo in state.todos[-20:]
                if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
            ],
            "repeated_todo_families": repeated_families,
            "guidance": (
                "These are advisory signals only. They do not block planning; use them to decide "
                "whether to stop, change strategy, or avoid semantically repeated attempts."
            ),
        }

    @staticmethod
    def _todo_family(goal: str) -> str:
        text = goal.lower()
        if "lfsr" in text:
            return "lfsr-analysis"
        if "disassembl" in text or "objdump" in text or "machine code" in text:
            return "binary-disassembly"
        if "decrypt" in text or "keystream" in text or "known-plaintext" in text:
            return "decrypt-keystream"
        if "flag" in text and any(token in text for token in ("recover", "validate", "candidate")):
            return "flag-recovery"
        if "run" in text and "binary" in text:
            return "binary-run"
        if "inventory" in text or "classify" in text:
            return "artifact-inventory"
        return "other"
