"""Render planner context as a JSON LLM prompt."""

from __future__ import annotations

import json
from typing import Any

from killchain_docker.orchestrator.planning.context_models import PlannerContext
from killchain_docker.orchestrator.planning.prompt_contract import PLANNING_CONTRACT


def render_planner_prompt(
    ctx: PlannerContext,
    *,
    require_action: bool = False,
    previous_summary: str | None = None,
) -> str:
    snapshot: dict[str, Any] = {
        "objective": ctx.objective,
        "authorized_scope": ctx.authorized_scope,
        "challenge_category": ctx.challenge_category,
        "planning_profiles": ctx.planning_profiles,
        "summary": ctx.state_summary,
        "assets": ctx.assets,
        "artifacts": ctx.artifacts,
        "endpoints": ctx.endpoints,
        "findings": ctx.findings,
        "credentials": ctx.credentials,
        "sessions": ctx.sessions,
        "flag_candidates": ctx.flag_candidates,
        "rejected_flag_candidates": ctx.rejected_flag_candidates,
        "todos": ctx.todos,
        "recent_round_summaries": ctx.recent_round_summaries,
        "recent_evidence_context": ctx.recent_evidence_context,
        "recent_execution_log": ctx.recent_execution_log,
        "stagnation_signals": ctx.stagnation,
        "near_miss_evidence": ctx.near_miss_evidence,
        "run_memory": ctx.run_memory,
        "cross_run_memory": ctx.cross_run_memory,
        "knowledge_augmentation": ctx.knowledge_augmentation,
    }
    if ctx.pivot_summaries:
        snapshot["pivot_required"] = ctx.pivot_summaries
    snapshot["planning_contract"] = {
        **PLANNING_CONTRACT,
        "open_todos": ctx.open_todo_count,
    }
    if require_action:
        snapshot["planner_retry_instruction"] = {
            "reason": "previous planner response returned no actionable todos without stop_run=true",
            "previous_summary": str(previous_summary or "")[:400],
            "required_response": "Return at least one grounded next todo that cites current state evidence, or set stop_run=true with a concise exhaustion reason.",
        }
    return json.dumps(snapshot, ensure_ascii=True, indent=2)
