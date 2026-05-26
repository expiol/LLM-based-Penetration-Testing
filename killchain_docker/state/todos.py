"""Todo, assignment, round, and worker-result models."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from killchain_docker.state.common import (
    coerce_text_items,
    make_id,
    parse_text_sequence,
    utc_now,
)
from killchain_docker.state.domain import (
    Asset,
    Credential,
    EvidenceRecord,
    Finding,
    NetworkEdge,
    StateDelta,
)
from killchain_docker.value_coercion import coerce_string_mapping


class TodoStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    INTERRUPTED = "interrupted"


class TodoPhase(StrEnum):
    RECON = "recon"
    ANALYSIS = "analysis"
    EXPLOIT = "exploit"
    FLAG_VALIDATION = "flag_validation"


TODO_PHASE_ORDER: tuple[TodoPhase, ...] = (
    TodoPhase.RECON,
    TodoPhase.ANALYSIS,
    TodoPhase.EXPLOIT,
    TodoPhase.FLAG_VALIDATION,
)

_TODO_PHASE_RANK: dict[TodoPhase, int] = {
    phase: index for index, phase in enumerate(TODO_PHASE_ORDER)
}


def normalize_todo_phase(value: Any) -> TodoPhase:
    """Return a canonical todo phase."""
    if isinstance(value, TodoPhase):
        return value
    if value is None:
        return TodoPhase.RECON
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not normalized:
        return TodoPhase.RECON
    return TodoPhase(normalized)


def todo_phase_rank(phase: TodoPhase | str | None) -> int:
    """Return the ordered kill-chain rank for a todo phase."""
    return _TODO_PHASE_RANK[normalize_todo_phase(phase)]


class TodoItem(BaseModel):
    """High-level planner task consumed by the router and persona workers."""

    model_config = ConfigDict(validate_assignment=True)

    todo_id: str = Field(default_factory=lambda: make_id("todo"))
    goal: str
    phase: TodoPhase = TodoPhase.RECON
    context: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=50, ge=0, le=100)
    success_criteria: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    status: TodoStatus = TodoStatus.PENDING
    assigned_worker: str | None = None
    result_summary: str = ""
    dedupe_key: str | None = None
    depends_on: list[str] = Field(default_factory=list)
    attempts: int = 0
    max_attempts: int = Field(default=2, ge=1)
    error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("phase", mode="before")
    @classmethod
    def _coerce_phase(cls, value: Any) -> TodoPhase:
        return normalize_todo_phase(value)

    @field_validator("depends_on", mode="before")
    @classmethod
    def _coerce_depends_on(cls, value: Any) -> list[str]:
        if value in (None, "", {}, ()):
            return []
        if isinstance(value, (list, tuple, set)):
            return coerce_text_items(value)
        text = str(value).strip()
        parsed = parse_text_sequence(text)
        if parsed is not None:
            return coerce_text_items(parsed)
        return [text] if text else []


class WorkerAssignment(BaseModel):
    """Router-selected mapping from one todo to one persona worker."""

    assignment_id: str = Field(default_factory=lambda: make_id("assignment"))
    todo_id: str
    worker_name: str
    rationale: str = ""


class RouterDecision(BaseModel):
    """Router output for one cycle before execution."""

    assignments: list[WorkerAssignment] = Field(default_factory=list)
    rationale: str = ""


class WorkerResult(BaseModel):
    """Structured result returned by a persona worker."""

    todo_id: str
    worker_name: str
    success: bool
    summary: str
    output_context: dict[str, Any] = Field(default_factory=dict)
    asset_updates: list[Asset] = Field(default_factory=list)
    finding_updates: list[Finding] = Field(default_factory=list)
    credential_updates: list[Credential] = Field(default_factory=list)
    network_updates: list[NetworkEdge] = Field(default_factory=list)
    state_delta: StateDelta = Field(default_factory=StateDelta)
    evidence_updates: list[EvidenceRecord] = Field(default_factory=list)
    suggested_todos: list[TodoItem] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    retryable: bool = True
    partial: bool = False
    result_quality: str | None = None
    partial_reason: str | None = None
    solved: bool = False
    validated_flag: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)
    memory_updates: dict[str, str] = Field(default_factory=dict)

    @field_validator("memory_updates", mode="before")
    @classmethod
    def _coerce_memory_updates(cls, value: Any) -> Any:
        return coerce_string_mapping(value)


class RouterRoundSummary(BaseModel):
    """Router synthesis for one execution round."""

    summary: str = ""
    direct_results: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)
    next_focus: str = ""
    used_llm: bool = False


class RouterRound(BaseModel):
    """One plan-route-execute-summarize cycle."""

    round_id: str = Field(default_factory=lambda: make_id("round"))
    cycle: int
    planner_summary: str = ""
    assignments: list[WorkerAssignment] = Field(default_factory=list)
    results: list[WorkerResult] = Field(default_factory=list)
    summary: RouterRoundSummary = Field(default_factory=RouterRoundSummary)
    created_at: datetime = Field(default_factory=utc_now)
