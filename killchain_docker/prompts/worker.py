"""System prompt builder for evidence-analysis workers."""

from __future__ import annotations

from killchain_docker.prompts.types import lookup


def build_worker_system_prompt(
    category: str | None,
    *,
    worker_role: str,
    evidence_type: str,
    output_schema: str,
) -> str:
    """Build a category-aware worker system prompt."""
    prompts = lookup(category)
    return (
        f"{prompts.worker_system_prefix}"
        f"{worker_role} "
        f"Return only JSON matching the {output_schema} schema. "
        f"Only emit grounded_flag_candidates and interesting_paths that are directly "
        f"supported by the provided {evidence_type} evidence. "
        "Do not fabricate flags, credentials, or paths not present in the evidence."
    )
