"""Prompt registry exposed as a single import surface."""

from __future__ import annotations

# Importing categories registers each bundle into the global registry.
from killchain_docker.prompts import categories  # noqa: F401
from killchain_docker.prompts.planner import build_planner_system_prompt
from killchain_docker.prompts.types import CategoryPrompts, lookup


def get_prompts(category: str | None) -> CategoryPrompts:
    return lookup(category)


def get_planner_system_prompt(category: str | None) -> str:
    return build_planner_system_prompt(category)


__all__ = [
    "CategoryPrompts",
    "get_planner_system_prompt",
    "get_prompts",
]
