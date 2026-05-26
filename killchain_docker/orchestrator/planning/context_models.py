"""Typed planner prompt context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class PlannerContext:
    """Fields consumed when rendering the planner prompt."""

    objective: str = ""
    authorized_scope: list[str] = field(default_factory=list)
    challenge_category: str = "misc"
    planning_profiles: list[dict[str, object]] = field(default_factory=list)
    state_summary: dict[str, Any] = field(default_factory=dict)
    assets: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    flag_candidates: list[dict[str, Any]] = field(default_factory=list)
    rejected_flag_candidates: list[dict[str, Any]] = field(default_factory=list)
    todos: list[dict[str, Any]] = field(default_factory=list)
    recent_round_summaries: list[dict[str, Any]] = field(default_factory=list)
    recent_evidence_context: list[dict[str, Any]] = field(default_factory=list)
    recent_execution_log: list[dict[str, Any]] = field(default_factory=list)
    run_memory: dict[str, str] = field(default_factory=dict)
    stagnation: dict[str, Any] = field(default_factory=dict)
    near_miss_evidence: list[dict[str, Any]] = field(default_factory=list)
    pivot_summaries: list[dict[str, Any]] = field(default_factory=list)
    knowledge_augmentation: dict[str, Any] = field(default_factory=dict)
    open_todo_count: int = 0
    temperature: float = 0.2
