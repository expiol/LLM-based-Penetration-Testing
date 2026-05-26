"""Planner schemas for high-level todo generation."""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Any
from pydantic import BaseModel, Field, field_validator
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, normalize_todo_phase

_PRIORITY_WORD_TO_INT: dict[str, int] = {
    "lowest": 10,
    "very_low": 15,
    "very low": 15,
    "low": 25,
    "minor": 25,
    "medium": 50,
    "med": 50,
    "normal": 50,
    "default": 50,
    "moderate": 50,
    "high": 75,
    "important": 75,
    "very_high": 85,
    "very high": 85,
    "urgent": 90,
    "critical": 95,
    "highest": 100,
}


class PlannedTodo(BaseModel):
    """High-level todo emitted by the planner."""

    goal: str
    phase: TodoPhase = TodoPhase.RECON
    context: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    dedupe_key: str | None = None
    depends_on: list[str] = Field(default_factory=list)

    @field_validator("priority", mode="before")
    @classmethod
    def _coerce_priority(cls, value: Any) -> Any:
        if isinstance(value, str):
            mapped = _PRIORITY_WORD_TO_INT.get(value.strip().lower())
            if mapped is not None:
                return mapped
            try:
                return int(value.strip())
            except ValueError:
                return value
        return value

    @field_validator("phase", mode="before")
    @classmethod
    def _coerce_phase(cls, value: Any) -> TodoPhase:
        return normalize_todo_phase(value)

    @field_validator("depends_on", mode="before")
    @classmethod
    def _coerce_depends_on(cls, value: Any) -> list[str]:
        return TodoItem(goal="_", depends_on=value).depends_on

    def to_todo(self) -> TodoItem:
        return TodoItem(
            goal=self.goal,
            phase=self.phase,
            context=self.context,
            priority=self.priority,
            success_criteria=self.success_criteria,
            constraints=self.constraints,
            dedupe_key=self.dedupe_key,
            depends_on=self.depends_on,
        )


class PlannerDecision(BaseModel):
    """Planner output before todos are merged into the live queue."""

    summary: str
    todos: list[PlannedTodo] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    stop_run: bool = False


class PlannerAgent(ABC):
    """Planner that proposes high-level todos from the latest run state."""

    @abstractmethod
    def plan(self, state: RunState) -> PlannerDecision:
        """Return high-level todos to merge into the queue."""
