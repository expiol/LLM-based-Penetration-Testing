"""Schemas and the abstract :class:`TaskPlanner` base."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field, field_validator

from killchain_docker.state import GlobalState, Task

_PRIORITY_WORD_TO_INT: dict[str, int] = {
    "lowest": 10, "very_low": 15, "very low": 15,
    "low": 25, "minor": 25,
    "medium": 50, "med": 50, "normal": 50, "default": 50, "moderate": 50,
    "high": 75, "important": 75,
    "very_high": 85, "very high": 85, "urgent": 90,
    "critical": 95, "highest": 100,
}

# When a planner emits a sprawling solver title like
# "Comprehensive FuelPHP source analysis & live exploitation: extract
# encryption keys, forge admin session cookie, bypass auth, and exploit
# /uploadify/uploadify.php for RCE to read flag", the resulting solver
# script tries to do everything at once and learns nothing.  We cap the
# title length and strip the multi-conjunction tail so the LLM is forced
# into a single concrete experiment per task.
_PLANNED_TASK_TITLE_MAX_CHARS = 80

# Words that signal "do everything in one script" — when seen at the start
# of a solver task title they're stripped because they don't help the worker.
_PLANNED_TASK_BROAD_PREFIXES = (
    "comprehensive", "deep analysis", "deep ", "full ", "complete ",
    "extensive ", "thorough ", "end-to-end ", "all-in-one ",
)

#: Conjunction tokens that join multiple experiments in one title.  When
#: more than ``_PLANNED_TASK_MAX_CONJUNCTIONS`` are present we cut the
#: title at the first conjunction so the worker tackles only the first
#: stated step.  Plain commas count as conjunctions because solver titles
#: like "Extract source, forge cookie, exploit upload" are equivalent in
#: scope to the explicit-and form.
_PLANNED_TASK_CONJUNCTION_RE = re.compile(
    r"\s*(?:,\s*and\s+|\s+and\s+|\s*&\s*|\s+then\s+|\s*;\s*|,\s+)",
    re.IGNORECASE,
)
_PLANNED_TASK_MAX_CONJUNCTIONS = 1


def _narrow_solver_title(title: str) -> str:
    """Trim broad-prefix and multi-step conjunctions from a solver title.

    Idempotent.  Returns the original *title* when it is already focused
    (single experiment, ≤ :data:`_PLANNED_TASK_TITLE_MAX_CHARS`).
    """
    if not title:
        return title
    cleaned = title.strip()

    # Strip "Comprehensive" / "Deep analysis" / "Full" -style superlatives
    # at the start.  Case-insensitive single pass.
    low = cleaned.lower()
    for prefix in _PLANNED_TASK_BROAD_PREFIXES:
        if low.startswith(prefix):
            cleaned = cleaned[len(prefix):].lstrip(" :-,")
            low = cleaned.lower()
            break

    # Cut at the first conjunction past the configured limit.
    parts = _PLANNED_TASK_CONJUNCTION_RE.split(cleaned)
    if len(parts) > _PLANNED_TASK_MAX_CONJUNCTIONS + 1:
        cleaned = parts[0].rstrip(" ,;:-")

    if len(cleaned) > _PLANNED_TASK_TITLE_MAX_CHARS:
        cleaned = cleaned[: _PLANNED_TASK_TITLE_MAX_CHARS].rsplit(" ", 1)[0].rstrip(" ,;:-")
    if not cleaned:
        # Fallback to the head of the original title so we never produce ""
        cleaned = title.strip()[:_PLANNED_TASK_TITLE_MAX_CHARS] or "Solve"
    return cleaned


class PlannedTask(BaseModel):
    """Normalised task specification emitted by a planner."""

    title: str
    description: str
    task_type: str
    priority: int = Field(default=50, ge=0, le=100)
    input_context: dict[str, Any] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)
    dedupe_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("priority", mode="before")
    @classmethod
    def _coerce_priority(cls, value: Any) -> Any:
        """Accept LLM-friendly priority labels (`'high'`, `'medium'`, ...) as ints.

        Models occasionally emit the qualitative word; treat it as a synonym for
        the canonical integer band rather than crashing the whole plan.
        """
        if isinstance(value, str):
            mapped = _PRIORITY_WORD_TO_INT.get(value.strip().lower())
            if mapped is not None:
                return mapped
            try:
                return int(value.strip())
            except ValueError:
                return value
        return value

    def model_post_init(self, __context: Any) -> None:
        """Force solver task titles into single-experiment shape.

        Other task types are not narrowed because their titles tend to be
        deterministic (``"Validate candidate flag"``, ``"Probe interesting
        paths for seed-asset"``).  Solver titles, on the other hand, are
        whatever sentence the LLM picks and historically grow into
        ``"Comprehensive ... extract & analyze & forge & exploit & ..."``
        within a few cycles.
        """
        if self.task_type.startswith("solve."):
            narrowed = _narrow_solver_title(self.title)
            if narrowed != self.title:
                # Bypass validate_assignment by writing through __dict__.
                self.__dict__["title"] = narrowed

    def to_task(self) -> Task:
        return Task(
            title=self.title,
            description=self.description,
            task_type=self.task_type,
            priority=self.priority,
            input_context=self.input_context,
            dependencies=self.dependencies,
            dedupe_key=self.dedupe_key,
            metadata=self.metadata,
        )


class PlannerDecision(BaseModel):
    """Planner output before tasks are merged into the live task chain."""

    summary: str
    tasks: list[PlannedTask] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    stop_run: bool = False


class TaskPlanner(ABC):
    """Planner that proposes follow-up work from the latest global state."""

    @abstractmethod
    def plan(self, state: GlobalState) -> PlannerDecision:
        """Return task updates to merge into the task chain."""
