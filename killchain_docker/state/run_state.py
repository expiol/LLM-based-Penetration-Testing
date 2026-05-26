"""Durable run state model."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from killchain_docker.state.common import make_id, utc_now
from killchain_docker.state.domain import (
    Artifact,
    Asset,
    Credential,
    Endpoint,
    EvidenceRecord,
    ExecutionRecord,
    ExploitAttempt,
    Finding,
    FlagCandidate,
    Hypothesis,
    NetworkEdge,
    RejectedFlagCandidate,
    Route,
    Session,
    Vulnerability,
)
from killchain_docker.state.todos import RouterRound, TodoItem
from killchain_docker.value_coercion import coerce_string_mapping


class RunStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    SOLVED = "solved"
    FAILED = "failed"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


# FIFO caps applied at write time so a long batch run cannot bloat state.json
# past hundreds of MB. Prompt serializers trim further when feeding LLMs.
EXECUTION_LOG_LIMIT = 500
NOTES_LIMIT = 500
ORCHESTRATION_NOTES_LIMIT = 500
EVIDENCE_DICT_LIMIT = 800
TYPED_FACT_DICT_LIMIT = 800
REJECTED_FLAG_CANDIDATE_LIMIT = 120


class RunState(BaseModel):
    """Planner-router-worker state for the persona-agent runtime."""

    model_config = ConfigDict(validate_assignment=True)

    run_id: str = Field(default_factory=lambda: make_id("run"))
    objective: str
    authorized_scope: list[str] = Field(default_factory=list)
    status: RunStatus = RunStatus.IDLE
    metadata: dict[str, Any] = Field(default_factory=dict)
    todos: list[TodoItem] = Field(default_factory=list)
    rounds: list[RouterRound] = Field(default_factory=list)
    assets: dict[str, Asset] = Field(default_factory=dict)
    findings: dict[str, Finding] = Field(default_factory=dict)
    credentials: dict[str, Credential] = Field(default_factory=dict)
    artifacts: dict[str, Artifact] = Field(default_factory=dict)
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    routes: dict[str, Route] = Field(default_factory=dict)
    flag_candidates: dict[str, FlagCandidate] = Field(default_factory=dict)
    rejected_flag_candidates: list[RejectedFlagCandidate] = Field(default_factory=list)
    hypotheses: dict[str, Hypothesis] = Field(default_factory=dict)
    vulnerabilities: dict[str, Vulnerability] = Field(default_factory=dict)
    exploit_attempts: dict[str, ExploitAttempt] = Field(default_factory=dict)
    sessions: dict[str, Session] = Field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = Field(default_factory=dict)
    network_edges: list[NetworkEdge] = Field(default_factory=list)
    execution_log: list[ExecutionRecord] = Field(default_factory=list)
    run_memory: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    orchestration_notes: list[str] = Field(default_factory=list)
    solved: bool = False
    validated_flag: str | None = None
    stop_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_cycle_at: datetime | None = None

    @field_validator("run_memory", mode="before")
    @classmethod
    def _coerce_run_memory(cls, value: Any) -> Any:
        return coerce_string_mapping(value)
