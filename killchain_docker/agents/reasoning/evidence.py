"""LLM-assisted post-processing for evidence-heavy artifact workers.

The seven artifact-review workers (binary, source, computation, runtime,
sqlite, pcap, repo) all follow the same pattern:

  1. Run a plugin to produce a structured evidence bundle.
  2. Send the bundle to the LLM, asking for grounded flag candidates,
     interesting paths, and recommended checks (the
     :class:`EvidenceReviewGuidance` schema).
  3. Merge the LLM result back into the worker output context.

This module owns step 2-3 so the workers themselves stay short.
"""

from __future__ import annotations

import json
from typing import Any, TYPE_CHECKING

from killchain_docker.agents._helpers.strings import merge_unique_strings
from killchain_docker.agents.reasoning.schemas import EvidenceReviewGuidance
from killchain_docker.prompts import get_analysis_strategy, get_worker_system_prompt
from killchain_docker.state import GlobalState, Task

if TYPE_CHECKING:
    from killchain_docker.agents.base import WorkerAgent
    from killchain_docker.tools.core import ToolExecutionBundle


def review_evidence_with_llm(
    worker: "WorkerAgent",
    *,
    state: GlobalState,
    task: Task,
    bundle: "ToolExecutionBundle",
    evidence_label: str,
    role_addition: str = "",
) -> EvidenceReviewGuidance:
    """Ask the LLM to enrich evidence-heavy plugin output.

    Raises ``LLMClientError`` when the LLM client is not configured or the call
    fails; callers should let the run fail fast.
    """
    challenge_meta = state.metadata.get("challenge", {}) or {}
    challenge_category = str(challenge_meta.get("category") or "").lower()

    role = (
        f"You analyze structured {evidence_label} evidence from an authorized CTF workflow. "
        f"Return only JSON matching the EvidenceReviewGuidance schema. "
        f"Only emit grounded_flag_candidates or interesting_paths that are directly supported by the "
        f"observed evidence. "
        + (role_addition or "")
        + " "
        + get_analysis_strategy(challenge_category)
    )

    system_prompt = get_worker_system_prompt(
        challenge_category,
        worker_role=role,
        evidence_type=evidence_label,
        output_schema="EvidenceReviewGuidance",
    )

    user_prompt = json.dumps(
        {
            "objective": state.objective,
            "task_id": task.task_id,
            "challenge": {
                "category": challenge_meta.get("category"),
                "flag_format": challenge_meta.get("flag_format"),
            },
            f"{evidence_label}_summary": bundle.parsed.summary,
            f"{evidence_label}_output_context": bundle.parsed.output_context,
            "known_assets": [
                {"asset_id": asset.asset_id, "base_url": asset.base_url}
                for asset in state.assets.values()
                if asset.base_url
            ],
        },
        ensure_ascii=True,
        indent=2,
    )

    return worker.generate_structured_output(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        schema=EvidenceReviewGuidance,
    )


def merge_evidence_review(
    output_context: dict[str, Any],
    flag_candidates: list[str],
    guidance: EvidenceReviewGuidance,
    *,
    flag_limit: int = 12,
    check_limit: int = 8,
    path_limit: int | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Merge an :class:`EvidenceReviewGuidance` result into worker output context.

    Returns the (output_context, flag_candidates) tuple after merging.
    """
    manual_checks = list(output_context.get("manual_checks") or [])
    flag_candidates = merge_unique_strings(
        flag_candidates,
        guidance.grounded_flag_candidates,
        limit=flag_limit,
    )
    manual_checks = merge_unique_strings(
        manual_checks,
        guidance.recommended_checks,
        limit=check_limit,
    )
    if path_limit is not None:
        output_context["interesting_routes"] = merge_unique_strings(
            output_context.get("interesting_routes") or [],
            guidance.interesting_paths,
            limit=path_limit,
        )
    output_context["llm_summary"] = guidance.summary

    output_context["flag_candidates"] = flag_candidates
    output_context["manual_checks"] = manual_checks
    return output_context, flag_candidates
