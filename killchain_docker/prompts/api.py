"""Public prompt-package API.

This module triggers registration of all category bundles by importing the
``categories`` subpackage at module load, then exposes the convenience
functions used elsewhere in the project.
"""

from __future__ import annotations

# Importing categories registers each bundle into the global registry.
from killchain_docker.prompts import categories  # noqa: F401
from killchain_docker.prompts.planner import build_planner_system_prompt
from killchain_docker.prompts.types import CategoryPrompts, lookup


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
