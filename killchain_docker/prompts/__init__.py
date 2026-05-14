"""Prompt registry exposed as a single import surface.

Each CTF category (web, crypto, rev, pwn, forensics, misc) lives in its own
module under :mod:`prompts.categories`. Planner and category bundles are split
into separate modules so each piece can be edited independently.

Public API:

- :func:`get_prompts` — return the :class:`CategoryPrompts` bundle for a category
- :func:`get_objective_hint` — render a category-specific objective sentence
- :func:`get_planner_system_prompt` — build the planner system prompt
"""

from killchain_docker.prompts.api import (
    get_objective_hint,
    get_planner_system_prompt,
    get_prompts,
)
from killchain_docker.prompts.types import CategoryPrompts

__all__ = [
    "CategoryPrompts",
    "get_objective_hint",
    "get_planner_system_prompt",
    "get_prompts",
]
