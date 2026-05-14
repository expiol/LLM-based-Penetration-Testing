"""Public prompt-package API.

This module triggers registration of all category bundles by importing the
``categories`` subpackage at module load, then exposes the convenience
functions used elsewhere in the project.
"""

from __future__ import annotations

from typing import Any

# Importing categories registers each bundle into the global registry.
from killchain_docker.prompts import categories  # noqa: F401
from killchain_docker.prompts.planner import build_planner_system_prompt
from killchain_docker.prompts.types import CategoryPrompts, lookup
from killchain_docker.prompts.worker import build_worker_system_prompt


def get_prompts(category: str | None) -> CategoryPrompts:
    """Return the prompt bundle for *category*, falling back to misc."""
    return lookup(category)


def get_objective_hint(category: str | None, *, has_files: bool, has_scope: bool) -> str:
    """Return a focused objective hint paragraph for the given category."""
    prompts = lookup(category)
    parts = [prompts.objective_hint]
    if has_files and not has_scope:
        parts.append(
            "Challenge files are available inside the agent container under "
            "/home/ctfplayer/ctf_files. Inspect them first and derive concrete "
            "flag candidates from the local artifacts."
        )
    return " ".join(parts)


def get_planner_system_prompt(category: str | None) -> str:
    """Build the LLM planner system prompt for the given category."""
    return build_planner_system_prompt(category)


def get_worker_system_prompt(
    category: str | None,
    *,
    worker_role: str,
    evidence_type: str,
    output_schema: str,
) -> str:
    """Build a category-aware worker system prompt."""
    return build_worker_system_prompt(
        category,
        worker_role=worker_role,
        evidence_type=evidence_type,
        output_schema=output_schema,
    )


def get_analysis_strategy(category: str | None) -> str:
    """Return the analysis strategy text for the given category."""
    return lookup(category).analysis_strategy


def get_exploit_strategy(category: str | None) -> str:
    """Return the exploit strategy text for the given category."""
    return lookup(category).exploit_strategy


def get_flag_hints(category: str | None) -> list[str]:
    """Return category-specific flag recovery hints."""
    return list(lookup(category).flag_recovery_hints)


def build_worker_context(state_metadata: dict[str, Any]) -> dict[str, str]:
    """Extract category and return useful prompt fragments for workers."""
    challenge = state_metadata.get("challenge", {})
    category = str(challenge.get("category") or "misc").lower()
    prompts = lookup(category)
    return {
        "category": category,
        "analysis_strategy": prompts.analysis_strategy,
        "exploit_strategy": prompts.exploit_strategy,
        "worker_system_prefix": prompts.worker_system_prefix,
        "flag_hints": "\n".join(f"- {hint}" for hint in prompts.flag_recovery_hints),
    }
