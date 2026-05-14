"""Prompt registry exposed as a single import surface.

Each CTF category (web, crypto, rev, pwn, forensics, misc) lives in its own
module under :mod:`prompts.categories`. Planner, dispatch, and worker prompts
are split into separate modules so each piece can be edited independently.

Public API:

- :func:`get_prompts` — return the :class:`CategoryPrompts` bundle for a category
- :func:`get_objective_hint` — render a category-specific objective sentence
- :func:`get_planner_system_prompt` — build the planner system prompt
- :func:`get_worker_system_prompt` — build a worker system prompt
- :func:`get_analysis_strategy` / :func:`get_exploit_strategy` /
  :func:`get_flag_hints` - category-specific text fragments
- :func:`build_worker_context` — quick dict for in-task LLM context
"""

from killchain_docker.prompts.api import (
    build_worker_context,
    get_analysis_strategy,
    get_exploit_strategy,
    get_flag_hints,
    get_objective_hint,
    get_planner_system_prompt,
    get_prompts,
    get_worker_system_prompt,
)
from killchain_docker.prompts.types import CategoryPrompts

__all__ = [
    "CategoryPrompts",
    "build_worker_context",
    "get_analysis_strategy",
    "get_exploit_strategy",
    "get_flag_hints",
    "get_objective_hint",
    "get_planner_system_prompt",
    "get_prompts",
    "get_worker_system_prompt",
]
