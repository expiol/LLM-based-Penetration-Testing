"""Prompt registry exposed as a single import surface.

Each CTF category (web, crypto, rev, pwn, forensics, misc) lives in its own
module under :mod:`prompts.categories`.  Planner, router, worker, and solver
prompts are split into separate modules so each piece can be edited
independently.

Public API:

- :func:`get_prompts` — return the :class:`CategoryPrompts` bundle for a category
- :func:`get_objective_hint` — render a category-specific objective sentence
- :func:`get_planner_system_prompt` — build the planner system prompt
- :func:`get_router_system_prompt` — build the router system prompt
- :func:`get_worker_system_prompt` — build a worker system prompt
- :func:`get_analysis_strategy` / :func:`get_exploit_strategy` /
  :func:`get_flag_hints` / :func:`get_solver_technique_examples` —
  category-specific text fragments
- :func:`build_worker_context` — quick dict for in-task LLM context
- :func:`build_solver_system_prompt` — solver-specific system prompt
"""

from killchain_docker.prompts.api import (
    build_solver_system_prompt,
    build_worker_context,
    get_analysis_strategy,
    get_exploit_strategy,
    get_flag_hints,
    get_objective_hint,
    get_planner_system_prompt,
    get_prompts,
    get_router_system_prompt,
    get_solver_technique_examples,
    get_worker_system_prompt,
)
from killchain_docker.prompts.types import CategoryPrompts

__all__ = [
    "CategoryPrompts",
    "build_solver_system_prompt",
    "build_worker_context",
    "get_analysis_strategy",
    "get_exploit_strategy",
    "get_flag_hints",
    "get_objective_hint",
    "get_planner_system_prompt",
    "get_prompts",
    "get_router_system_prompt",
    "get_solver_technique_examples",
    "get_worker_system_prompt",
]
