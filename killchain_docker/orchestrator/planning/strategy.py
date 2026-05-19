"""LLM-driven high-level todo proposal."""

from __future__ import annotations

import json

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.context import PlannerContextBuilder
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.state import RunState


# Planning contract injected into every planner prompt
_PLANNING_CONTRACT = {
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
        "Only propose exploit-phase todos without explicit ids when the current state already contains "
        "grounded vulnerabilities, credentials, or sessions. Findings, hypotheses, and evidence must be "
        "cited with explicit ids from the current state in todo context."
    ),
    "stop_rule": "Set stop_run=true only when solved or genuinely exhausted.",
    "evidence_context_rule": (
        "Use recent_evidence_context as grounded facts from completed tools. "
        "Do not re-request hexdumps, stdout, binary traits, or disassembly snippets "
        "that are already present there; plan the next distinct step from that evidence. "
        "Do not plan work that depends on /tmp files written by an earlier todo. "
        "If raw data is needed, use recent_evidence_context or regenerate and print it in the same script."
    ),
    "novelty_rule": (
        "When stagnation_signals lists a cooled-down family, a new todo in that family "
        "must cite current-state context.evidence_ids or context.hypothesis_id/context.hypothesis_ids "
        "that were not used by previous todos in that family. context.novelty_key may label "
        "the new approach, but it is not grounding by itself. Rephrasing the goal is not novelty."
    ),
}


class PlanStrategy:
    """Submit the current run state to the LLM and return high-level todos."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        if llm_client is None:
            raise LLMClientError("PlanStrategy requires an LLM client.")
        self.llm_client = llm_client
        self.context_builder = PlannerContextBuilder(augmenter=augmenter)

    def propose(self, state: RunState) -> PlannerDecision:
        ctx = self.context_builder.build(state)
        return self.llm_client.generate_json(
            system_prompt=self.context_builder.system_prompt(state),
            user_prompt=self._render_prompt(ctx),
            schema=PlannerDecision,
            temperature=ctx.temperature,
        )

    @staticmethod
    def _render_prompt(ctx) -> str:
        """Render PlannerContext into the JSON prompt string for the LLM."""
        snapshot = {
            "objective": ctx.objective,
            "authorized_scope": ctx.authorized_scope,
            "challenge_category": ctx.challenge_category,
            "analysis_strategy": ctx.analysis_strategy,
            "exploit_strategy": ctx.exploit_strategy,
            "flag_recovery_hints": ctx.flag_recovery_hints,
            "summary": ctx.state_summary,
            "assets": ctx.assets,
            "findings": ctx.findings,
            "flag_candidates": ctx.flag_candidates,
            "rejected_flag_candidates": ctx.rejected_flag_candidates,
            "todos": ctx.todos,
            "recent_round_summaries": ctx.recent_round_summaries,
            "recent_evidence_context": ctx.recent_evidence_context,
            "recent_execution_log": ctx.recent_execution_log,
            "stagnation_signals": ctx.stagnation,
            "near_miss_evidence": ctx.near_miss_evidence,
            "working_memory": ctx.working_memory,
        }
        if ctx.pivot_summaries:
            snapshot["pivot_required"] = ctx.pivot_summaries
        if ctx.related_writeups:
            snapshot["related_writeups"] = ctx.related_writeups
            if ctx.related_writeups_warning:
                snapshot["related_writeups_warning"] = ctx.related_writeups_warning
        snapshot["planning_contract"] = {
            **_PLANNING_CONTRACT,
            "open_todos": ctx.open_todo_count,
        }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)
