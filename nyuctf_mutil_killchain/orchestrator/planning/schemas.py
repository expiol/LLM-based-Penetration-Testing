"""Schemas and the abstract :class:`TaskPlanner` base."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field, field_validator

from nyuctf_mutil_killchain.state import GlobalState, Task

_PRIORITY_WORD_TO_INT: dict[str, int] = {
    "lowest": 10, "very_low": 15, "very low": 15,
    "low": 25, "minor": 25,
    "medium": 50, "med": 50, "normal": 50, "default": 50, "moderate": 50,
    "high": 75, "important": 75,
    "very_high": 85, "very high": 85, "urgent": 90,
    "critical": 95, "highest": 100,
}


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
