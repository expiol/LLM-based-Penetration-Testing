"""Common types and registry for the prompts package."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CategoryPrompts:
    """Prompt bundle for one CTF category."""

    category: str
    objective_hint: str
    planner_system: str
    planner_focus: str
    worker_system_prefix: str
    analysis_strategy: str
    exploit_strategy: str
    flag_recovery_hints: list[str] = field(default_factory=list)
    script_technique_examples: list[str] = field(default_factory=list)


_REGISTRY: dict[str, CategoryPrompts] = {}


def register(prompts: CategoryPrompts) -> None:
    """Register a category bundle into the global registry."""
    _REGISTRY[prompts.category] = prompts


def lookup(category: str | None) -> CategoryPrompts:
    """Return the bundle for *category*, falling back to misc."""
    normalized = (category or "misc").strip().lower()
    return _REGISTRY[normalized] if normalized in _REGISTRY else _REGISTRY["misc"]
