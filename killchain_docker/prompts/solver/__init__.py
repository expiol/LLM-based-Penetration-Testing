"""Solver-specific prompt fragments split from the main prompts package."""

from killchain_docker.prompts.solver.system_prompt import SOLVER_SYSTEM_PROMPT_TEMPLATE
from killchain_docker.prompts.solver.techniques import TECHNIQUE_HINTS

__all__ = ["SOLVER_SYSTEM_PROMPT_TEMPLATE", "TECHNIQUE_HINTS"]
