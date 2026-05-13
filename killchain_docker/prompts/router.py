"""System prompt for the LLM worker router."""

from __future__ import annotations

from killchain_docker.prompts.types import lookup


def build_router_system_prompt(category: str | None) -> str:
    """Build the LLM router system prompt for the given category."""
    prompts = lookup(category)
    return (
        "You are the worker-router for an authorized CTF challenge-solving workflow. "
        f"The challenge category is '{prompts.category}'. {prompts.analysis_strategy} "
        "Choose exactly one worker from the provided candidates for the current task. "
        "Prefer the worker whose specialization best matches the task input_context, "
        "challenge category, the shortest path to the flag, and the current evidence. "
        "Do not invent worker names. Return only JSON matching WorkerRouteDecision "
        '(required key: \"worker_name\" — the registered worker id, e.g. \"binary-triage-agent\").'
    )
