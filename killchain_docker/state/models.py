"""Pydantic models for shared workflow state."""

from __future__ import annotations

from datetime import datetime, timezone
from killchain_docker._compat import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _make_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


def _run_id() -> str:
    return _make_id("run")


def _evidence_id() -> str:
    return _make_id("evidence")


def _artifact_id() -> str:
    return _make_id("artifact")


def _endpoint_id() -> str:
    return _make_id("endpoint")


def _route_id() -> str:
    return _make_id("route")


def _flag_candidate_id() -> str:
    return _make_id("flag-candidate")


def _hypothesis_id() -> str:
    return _make_id("hypothesis")


def _vulnerability_id() -> str:
    return _make_id("vuln")


def _exploit_attempt_id() -> str:
    return _make_id("exploit-attempt")


def _session_id() -> str:
    return _make_id("session")


def _severity_rank(value: "Severity") -> int:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order[value]


class RunStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    SOLVED = "solved"
    FAILED = "failed"
    STOPPED = "stopped"
    INTERRUPTED = "interrupted"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AssetKind(StrEnum):
    UNKNOWN = "unknown"
    HOST = "host"
    WEB_APPLICATION = "web_application"
    API = "api"
    SERVICE = "service"


class Service(BaseModel):
    """A network-facing service observed on an asset."""

    port: int = Field(ge=1, le=65535)
    protocol: str = "tcp"
    name: str | None = None
    product: str | None = None
    version: str | None = None

    def merge(self, other: "Service") -> None:
        if other.name:
            self.name = other.name
        if other.product:
            self.product = other.product
        if other.version:
            self.version = other.version


class Asset(BaseModel):
    """Tracked target asset."""

    model_config = ConfigDict(validate_assignment=True)

    asset_id: str
    kind: AssetKind = AssetKind.UNKNOWN
    hostname: str | None = None
    ip_address: str | None = None
    base_url: str | None = None
    tags: set[str] = Field(default_factory=set)
    services: list[Service] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Asset") -> None:
        if self.kind == AssetKind.UNKNOWN and other.kind != AssetKind.UNKNOWN:
            self.kind = other.kind
        if other.hostname:
            self.hostname = other.hostname
        if other.ip_address:
            self.ip_address = other.ip_address
        if other.base_url:
            self.base_url = other.base_url
        self.tags |= other.tags
        self.metadata.update(other.metadata)

        existing = {(service.port, service.protocol): service for service in self.services}
        for service in other.services:
            key = (service.port, service.protocol)
            if key in existing:
                existing[key].merge(service)
            else:
                self.services.append(service)

        self.updated_at = utc_now()


class Finding(BaseModel):
    """A security-relevant observation tied to one or more assets."""

    model_config = ConfigDict(validate_assignment=True)

    finding_id: str
    title: str
    severity: Severity = Severity.INFO
    description: str | None = None
    asset_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    status: str = "open"
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Finding") -> None:
        if _severity_rank(other.severity) > _severity_rank(self.severity):
            self.severity = other.severity
        if other.description:
            self.description = other.description
        self.asset_refs = sorted(set(self.asset_refs) | set(other.asset_refs))
        self.evidence_refs = sorted(set(self.evidence_refs) | set(other.evidence_refs))
        self.metadata.update(other.metadata)
        if other.status:
            self.status = other.status
        self.updated_at = utc_now()


class Credential(BaseModel):
    """Reference to a credential artifact without storing a raw secret inline."""

    model_config = ConfigDict(validate_assignment=True)

    credential_id: str
    username: str
    secret_ref: str
    credential_type: str = "unknown"
    asset_ref: str | None = None
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Credential") -> None:
        if other.asset_ref:
            self.asset_ref = other.asset_ref
        if other.source:
            self.source = other.source
        if other.secret_ref:
            self.secret_ref = other.secret_ref
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class NetworkEdge(BaseModel):
    """A directed relation between two assets or logical nodes."""

    source: str
    target: str
    relationship: str
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)


class Artifact(BaseModel):
    """Typed view of a challenge or generated artifact."""

    model_config = ConfigDict(validate_assignment=True)

    artifact_id: str = Field(default_factory=_artifact_id)
    path: str
    kind: str = "unknown"
    source: str | None = None
    size: int | None = None
    digest: str | None = None
    preview: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Artifact") -> None:
        if other.kind and self.kind == "unknown":
            self.kind = other.kind
        if other.source:
            self.source = other.source
        if other.size is not None:
            self.size = other.size
        if other.digest:
            self.digest = other.digest
        if other.preview:
            self.preview = other.preview
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class Endpoint(BaseModel):
    """Reachable host/service endpoint used by web, pwn, and exploit workers."""

    model_config = ConfigDict(validate_assignment=True)

    endpoint_id: str = Field(default_factory=_endpoint_id)
    asset_ref: str | None = None
    url: str | None = None
    hostname: str | None = None
    port: int | None = None
    protocol: str | None = None
    status_code: int | None = None
    title: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Endpoint") -> None:
        for field_name in ("asset_ref", "url", "hostname", "protocol", "title"):
            value = getattr(other, field_name)
            if value:
                setattr(self, field_name, value)
        if other.port is not None:
            self.port = other.port
        if other.status_code is not None:
            self.status_code = other.status_code
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class Route(BaseModel):
    """HTTP route or page observed during web exploration."""

    model_config = ConfigDict(validate_assignment=True)

    route_id: str = Field(default_factory=_route_id)
    endpoint_ref: str | None = None
    asset_ref: str | None = None
    url: str
    path: str | None = None
    method: str = "GET"
    status_code: int | None = None
    source: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Route") -> None:
        for field_name in ("endpoint_ref", "asset_ref", "url", "path", "method", "source"):
            value = getattr(other, field_name)
            if value:
                setattr(self, field_name, value)
        if other.status_code is not None:
            self.status_code = other.status_code
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class FlagCandidate(BaseModel):
    """Flag-like value plus provenance and validation status."""

    model_config = ConfigDict(validate_assignment=True)

    candidate_id: str = Field(default_factory=_flag_candidate_id)
    value: str
    source: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    validated: bool | None = None
    rejected_reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "FlagCandidate") -> None:
        if other.source:
            self.source = other.source
        self.confidence = max(self.confidence, other.confidence)
        if other.validated is not None:
            self.validated = other.validated
        if other.rejected_reason:
            self.rejected_reason = other.rejected_reason
        self.evidence_refs = sorted(set(self.evidence_refs) | set(other.evidence_refs))
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class Hypothesis(BaseModel):
    """An analysis or exploit hypothesis with outcome tracking."""

    model_config = ConfigDict(validate_assignment=True)

    hypothesis_id: str = Field(default_factory=_hypothesis_id)
    title: str
    description: str | None = None
    category: str | None = None
    status: str = "open"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Hypothesis") -> None:
        if other.description:
            self.description = other.description
        if other.category:
            self.category = other.category
        if other.status:
            self.status = other.status
        self.confidence = max(self.confidence, other.confidence)
        self.evidence_refs = sorted(set(self.evidence_refs) | set(other.evidence_refs))
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class Vulnerability(BaseModel):
    """Security weakness or challenge-specific exploit primitive."""

    model_config = ConfigDict(validate_assignment=True)

    vulnerability_id: str = Field(default_factory=_vulnerability_id)
    title: str
    severity: Severity = Severity.INFO
    asset_ref: str | None = None
    route_ref: str | None = None
    description: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Vulnerability") -> None:
        if _severity_rank(other.severity) > _severity_rank(self.severity):
            self.severity = other.severity
        for field_name in ("asset_ref", "route_ref", "description"):
            value = getattr(other, field_name)
            if value:
                setattr(self, field_name, value)
        self.evidence_refs = sorted(set(self.evidence_refs) | set(other.evidence_refs))
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class ExploitAttempt(BaseModel):
    """One concrete exploit or tool experiment and its observed result."""

    model_config = ConfigDict(validate_assignment=True)

    attempt_id: str = Field(default_factory=_exploit_attempt_id)
    task_id: str | None = None
    worker_name: str | None = None
    target_ref: str | None = None
    technique: str | None = None
    success: bool = False
    summary: str | None = None
    flag_candidate_refs: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "ExploitAttempt") -> None:
        for field_name in ("task_id", "worker_name", "target_ref", "technique", "summary"):
            value = getattr(other, field_name)
            if value:
                setattr(self, field_name, value)
        self.success = self.success or other.success
        self.flag_candidate_refs = sorted(
            set(self.flag_candidate_refs) | set(other.flag_candidate_refs)
        )
        self.evidence_refs = sorted(set(self.evidence_refs) | set(other.evidence_refs))
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class Session(BaseModel):
    """Authenticated or interactive session state discovered during exploitation."""

    model_config = ConfigDict(validate_assignment=True)

    session_id: str = Field(default_factory=_session_id)
    asset_ref: str | None = None
    endpoint_ref: str | None = None
    username: str | None = None
    session_type: str = "unknown"
    status: str = "active"
    secret_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "Session") -> None:
        for field_name in (
            "asset_ref", "endpoint_ref", "username", "session_type", "status", "secret_ref"
        ):
            value = getattr(other, field_name)
            if value:
                setattr(self, field_name, value)
        self.metadata.update(other.metadata)
        self.updated_at = utc_now()


class StateDelta(BaseModel):
    """Typed facts extracted from one tool or worker result."""

    artifacts: list[Artifact] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    flag_candidates: list[FlagCandidate] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    exploit_attempts: list[ExploitAttempt] = Field(default_factory=list)
    sessions: list[Session] = Field(default_factory=list)


class ExecutionRecord(BaseModel):
    """Compact audit entry for a worker dispatch."""

    task_id: str
    worker_name: str
    success: bool
    summary: str
    error: str | None = None
    recorded_at: datetime = Field(default_factory=utc_now)


class EvidenceRecord(BaseModel):
    """Tool evidence captured during a worker execution."""

    model_config = ConfigDict(validate_assignment=True)

    evidence_id: str = Field(default_factory=_evidence_id)
    task_id: str
    capability: str | None = None
    tool_name: str
    mode: str
    summary: str
    parser_name: str | None = None
    request: dict[str, Any] = Field(default_factory=dict)
    result: dict[str, Any] = Field(default_factory=dict)
    extracted: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def merge(self, other: "EvidenceRecord") -> None:
        if other.summary:
            self.summary = other.summary
        if other.parser_name:
            self.parser_name = other.parser_name
        if other.capability:
            self.capability = other.capability
        if other.mode:
            self.mode = other.mode
        self.request.update(other.request)
        self.result.update(other.result)
        self.extracted.update(other.extracted)
        self.updated_at = utc_now()


#: FIFO caps applied at write time so a long batch run cannot bloat
#: ``state.json`` past hundreds of MB. Caps are deliberately generous
#: (planner serialization trims further when feeding LLM prompts); they only
#: bound disk/RAM growth, not what the LLM sees.
EXECUTION_LOG_LIMIT = 500
NOTES_LIMIT = 500
ORCHESTRATION_NOTES_LIMIT = 500
EVIDENCE_DICT_LIMIT = 800
TYPED_FACT_DICT_LIMIT = 800


def _todo_id() -> str:
    return _make_id("todo")


def _assignment_id() -> str:
    return _make_id("assignment")


def _round_id() -> str:
    return _make_id("round")


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


_TODO_PHASE_ALIASES: dict[str, TodoPhase] = {
    "recon": TodoPhase.RECON,
    "discovery": TodoPhase.RECON,
    "enumeration": TodoPhase.RECON,
    "info_gathering": TodoPhase.RECON,
    "information_gathering": TodoPhase.RECON,
    "mapping": TodoPhase.RECON,
    "analysis": TodoPhase.ANALYSIS,
    "analyze": TodoPhase.ANALYSIS,
    "review": TodoPhase.ANALYSIS,
    "triage": TodoPhase.ANALYSIS,
    "vulnerability_identification": TodoPhase.ANALYSIS,
    "vuln_identification": TodoPhase.ANALYSIS,
    "exploit": TodoPhase.EXPLOIT,
    "exploitation": TodoPhase.EXPLOIT,
    "attack": TodoPhase.EXPLOIT,
    "poc": TodoPhase.EXPLOIT,
    "proof_of_concept": TodoPhase.EXPLOIT,
    "flag": TodoPhase.FLAG_VALIDATION,
    "flag_validation": TodoPhase.FLAG_VALIDATION,
    "flag_validate": TodoPhase.FLAG_VALIDATION,
    "validation": TodoPhase.FLAG_VALIDATION,
    "validate_flag": TodoPhase.FLAG_VALIDATION,
}


def normalize_todo_phase(value: Any) -> TodoPhase:
    """Coerce planner/legacy phase spellings into the canonical enum."""
    if isinstance(value, TodoPhase):
        return value
    if value is None:
        return TodoPhase.RECON
    normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not normalized:
        return TodoPhase.RECON
    return _TODO_PHASE_ALIASES.get(normalized, TodoPhase(normalized))


def todo_phase_rank(phase: TodoPhase | str | None) -> int:
    """Return the ordered kill-chain rank for a todo phase."""
    return _TODO_PHASE_RANK[normalize_todo_phase(phase)]


class TodoItem(BaseModel):
    """High-level planner task consumed by the router and persona workers."""

    model_config = ConfigDict(validate_assignment=True)

    todo_id: str = Field(default_factory=_todo_id)
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
    attempts: int = 0
    max_attempts: int = Field(default=2, ge=1)
    error: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("phase", mode="before")
    @classmethod
    def _coerce_phase(cls, value: Any) -> TodoPhase:
        return normalize_todo_phase(value)

    def is_ready(self) -> bool:
        return self.status == TodoStatus.PENDING

    def mark_running(self, worker_name: str) -> None:
        self.status = TodoStatus.RUNNING
        self.assigned_worker = worker_name
        self.attempts += 1
        self.error = None
        self.updated_at = utc_now()

    def mark_completed(self, summary: str) -> None:
        self.status = TodoStatus.COMPLETED
        self.result_summary = summary
        self.error = None
        self.updated_at = utc_now()

    def mark_partial(self, summary: str, reason: str | None = None) -> None:
        self.status = TodoStatus.PARTIAL
        self.result_summary = summary
        self.error = reason
        self.updated_at = utc_now()

    def mark_failed(self, error: str, *, retryable: bool) -> None:
        self.error = error
        if retryable and self.attempts < self.max_attempts:
            self.status = TodoStatus.PENDING
        else:
            self.status = TodoStatus.FAILED
        self.updated_at = utc_now()

    def mark_blocked(self, reason: str) -> None:
        self.status = TodoStatus.BLOCKED
        self.error = reason
        self.updated_at = utc_now()

    def mark_interrupted(self, reason: str) -> None:
        self.status = TodoStatus.INTERRUPTED
        self.error = reason
        self.updated_at = utc_now()


class WorkerAssignment(BaseModel):
    """Router-selected mapping from one todo to one persona worker."""

    assignment_id: str = Field(default_factory=_assignment_id)
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


class RouterRoundSummary(BaseModel):
    """Router synthesis for one execution round."""

    summary: str = ""
    direct_results: list[str] = Field(default_factory=list)
    key_findings: list[str] = Field(default_factory=list)
    next_focus: str = ""
    used_llm: bool = False


class RouterRound(BaseModel):
    """One plan-route-execute-summarize cycle."""

    round_id: str = Field(default_factory=_round_id)
    cycle: int
    planner_summary: str = ""
    assignments: list[WorkerAssignment] = Field(default_factory=list)
    results: list[WorkerResult] = Field(default_factory=list)
    summary: RouterRoundSummary = Field(default_factory=RouterRoundSummary)
    created_at: datetime = Field(default_factory=utc_now)


class RunState(BaseModel):
    """Planner-router-worker state for the persona-agent runtime."""

    model_config = ConfigDict(validate_assignment=True)

    run_id: str = Field(default_factory=_run_id)
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
    hypotheses: dict[str, Hypothesis] = Field(default_factory=dict)
    vulnerabilities: dict[str, Vulnerability] = Field(default_factory=dict)
    exploit_attempts: dict[str, ExploitAttempt] = Field(default_factory=dict)
    sessions: dict[str, Session] = Field(default_factory=dict)
    evidence: dict[str, EvidenceRecord] = Field(default_factory=dict)
    network_edges: list[NetworkEdge] = Field(default_factory=list)
    execution_log: list[ExecutionRecord] = Field(default_factory=list)
    working_memory: dict[str, str] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    orchestration_notes: list[str] = Field(default_factory=list)
    solved: bool = False
    validated_flag: str | None = None
    stop_reason: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_cycle_at: datetime | None = None

    def touch(self) -> None:
        self.updated_at = utc_now()
        self._enforce_caps()

    def _enforce_caps(self) -> None:
        if len(self.execution_log) > EXECUTION_LOG_LIMIT:
            del self.execution_log[: len(self.execution_log) - EXECUTION_LOG_LIMIT]
        if len(self.notes) > NOTES_LIMIT:
            del self.notes[: len(self.notes) - NOTES_LIMIT]
        if len(self.orchestration_notes) > ORCHESTRATION_NOTES_LIMIT:
            del self.orchestration_notes[
                : len(self.orchestration_notes) - ORCHESTRATION_NOTES_LIMIT
            ]
        if len(self.evidence) > EVIDENCE_DICT_LIMIT:
            excess = len(self.evidence) - EVIDENCE_DICT_LIMIT
            for evidence_id in list(self.evidence.keys())[:excess]:
                del self.evidence[evidence_id]
        for fact_dict in (
            self.artifacts,
            self.endpoints,
            self.routes,
            self.flag_candidates,
            self.hypotheses,
            self.vulnerabilities,
            self.exploit_attempts,
            self.sessions,
        ):
            if len(fact_dict) <= TYPED_FACT_DICT_LIMIT:
                continue
            excess = len(fact_dict) - TYPED_FACT_DICT_LIMIT
            for key in list(fact_dict.keys())[:excess]:
                del fact_dict[key]

    def queue_todo(self, todo: TodoItem) -> TodoItem:
        if not todo.dedupe_key:
            todo.dedupe_key = self.default_todo_key(todo)
        existing = next(
            (
                item for item in self.todos
                if item.dedupe_key == todo.dedupe_key
                and item.status in {
                    TodoStatus.PENDING,
                    TodoStatus.RUNNING,
                    TodoStatus.COMPLETED,
                    TodoStatus.PARTIAL,
                }
            ),
            None,
        )
        if existing is not None:
            self.touch()
            return existing
        self.todos.append(todo)
        self.touch()
        return todo

    def ready_todos(self, *, limit: int | None = None) -> list[TodoItem]:
        ready = [todo for todo in self.todos if todo.is_ready()]
        ready.sort(key=lambda item: (-item.priority, item.created_at))
        return ready[:limit] if limit is not None else ready

    def has_open_todos(self) -> bool:
        return any(todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING} for todo in self.todos)

    def get_todo(self, todo_id: str) -> TodoItem | None:
        return next((todo for todo in self.todos if todo.todo_id == todo_id), None)

    def upsert_asset(self, asset: Asset) -> None:
        if asset.asset_id in self.assets:
            self.assets[asset.asset_id].merge(asset)
        else:
            self.assets[asset.asset_id] = asset
        self.touch()

    def upsert_finding(self, finding: Finding) -> None:
        if finding.finding_id in self.findings:
            self.findings[finding.finding_id].merge(finding)
        else:
            self.findings[finding.finding_id] = finding
        self.touch()

    def upsert_credential(self, credential: Credential) -> None:
        if credential.credential_id in self.credentials:
            self.credentials[credential.credential_id].merge(credential)
        else:
            self.credentials[credential.credential_id] = credential
        self.touch()

    def upsert_evidence(self, evidence: EvidenceRecord) -> None:
        if evidence.evidence_id in self.evidence:
            self.evidence[evidence.evidence_id].merge(evidence)
        else:
            self.evidence[evidence.evidence_id] = evidence
        self.touch()

    def apply_state_delta(self, delta: StateDelta) -> None:
        for artifact in delta.artifacts:
            key = artifact.digest or artifact.path
            existing_id = next(
                (
                    current_id for current_id, current in self.artifacts.items()
                    if (artifact.digest and current.digest == artifact.digest)
                    or current.path == artifact.path
                ),
                None,
            )
            if existing_id is not None:
                self.artifacts[existing_id].merge(artifact)
            else:
                artifact.artifact_id = artifact.artifact_id or key
                self.artifacts[artifact.artifact_id] = artifact
        for endpoint in delta.endpoints:
            self.endpoints[endpoint.endpoint_id] = endpoint
        for route in delta.routes:
            self.routes[route.route_id] = route
        for candidate in delta.flag_candidates:
            from killchain_docker.orchestrator.policy import CandidatePolicy

            decision = CandidatePolicy.decision_for_state(self, candidate.value)
            if not decision.accepted:
                self.orchestration_notes.append(
                    f"Rejected flag candidate from {candidate.source or 'unknown'}: {decision.reason}"
                )
                continue
            existing_id = next(
                (
                    current_id for current_id, current in self.flag_candidates.items()
                    if current.value == candidate.value
                ),
                None,
            )
            if existing_id is not None:
                self.flag_candidates[existing_id].merge(candidate)
            else:
                self.flag_candidates[candidate.candidate_id] = candidate
        for hypothesis in delta.hypotheses:
            self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        for vulnerability in delta.vulnerabilities:
            self.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
        for attempt in delta.exploit_attempts:
            attempt.task_id = attempt.task_id or ""
            self.exploit_attempts[attempt.attempt_id] = attempt
        for session in delta.sessions:
            self.sessions[session.session_id] = session
        self.touch()

    def apply_worker_result(self, result: WorkerResult) -> None:
        todo = self.get_todo(result.todo_id)
        if todo is None:
            raise KeyError(f"Unknown todo id: {result.todo_id}")
        if result.partial:
            todo.mark_partial(result.summary, result.partial_reason or result.error)
        elif result.success:
            todo.mark_completed(result.summary)
        else:
            todo.mark_failed(result.error or result.summary, retryable=result.retryable)

        for asset in result.asset_updates:
            self.upsert_asset(asset)
        for finding in result.finding_updates:
            self.upsert_finding(finding)
        for credential in result.credential_updates:
            self.upsert_credential(credential)
        for evidence in result.evidence_updates:
            self.upsert_evidence(evidence)
        self.network_edges.extend(result.network_updates)
        self.apply_state_delta(result.state_delta)

        if result.memory_updates:
            self.working_memory.update(result.memory_updates)
            # Cap working memory at 20 entries
            if len(self.working_memory) > 20:
                excess = len(self.working_memory) - 20
                for key in list(self.working_memory.keys())[:excess]:
                    del self.working_memory[key]

        if result.solved:
            self.solved = True
            self.status = RunStatus.SOLVED
        if result.validated_flag:
            self.validated_flag = result.validated_flag
        self.execution_log.append(
            ExecutionRecord(
                task_id=result.todo_id,
                worker_name=result.worker_name,
                success=result.success,
                summary=result.summary,
                error=result.error,
            )
        )
        self.notes.extend(result.notes)
        self.touch()

    def record_round(self, round_record: RouterRound) -> None:
        self.rounds.append(round_record)
        self.touch()

    def interrupt_running_todos(self, reason: str) -> None:
        for todo in self.todos:
            if todo.status == TodoStatus.RUNNING:
                todo.mark_interrupted(reason)
        self.touch()

    def infer_asset_identity(self, ctx: dict[str, Any]) -> dict[str, str]:
        assets = self.assets
        if not assets:
            return {}
        filled: dict[str, str] = {}
        asset_id = ctx.get("asset_id")
        if asset_id and asset_id in assets:
            asset = assets[asset_id]
        elif len(assets) == 1:
            asset = next(iter(assets.values()))
            ctx.setdefault("asset_id", asset.asset_id)
            filled["asset_id"] = asset.asset_id
        else:
            return filled
        if not ctx.get("base_url") and asset.base_url:
            ctx["base_url"] = asset.base_url
            filled["base_url"] = asset.base_url
        if not ctx.get("hostname") and asset.hostname:
            ctx["hostname"] = asset.hostname
            filled["hostname"] = asset.hostname
        if not ctx.get("ports") and asset.services:
            ctx["ports"] = [service.port for service in asset.services]
            filled["ports"] = str(ctx["ports"])
        return filled

    @staticmethod
    def default_todo_key(todo: TodoItem) -> str:
        from killchain_docker.orchestrator.policy import TodoPolicy

        context = todo.context or {}
        if context:
            return TodoPolicy.default_key(todo)
        return f"todo:{todo.phase}:{todo.goal[:80]}"

    def active_flag_candidates(self) -> list[FlagCandidate]:
        from killchain_docker.orchestrator.policy import CandidatePolicy

        return CandidatePolicy.validation_ready_candidates(self)

    def todo_family_counts(self) -> dict[str, int]:
        from killchain_docker.orchestrator.policy import TodoPolicy

        counts: dict[str, int] = {}
        for todo in self.todos:
            family = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
            counts[family] = counts.get(family, 0) + 1
        return counts

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "stop_reason": self.stop_reason,
            "solved": self.solved,
            "validated_flag": self.validated_flag,
            "todos": len(self.todos),
            "open_todos": sum(1 for todo in self.todos if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}),
            "rounds": len(self.rounds),
            "assets": len(self.assets),
            "findings": len(self.findings),
            "credentials": len(self.credentials),
            "artifacts": len(self.artifacts),
            "endpoints": len(self.endpoints),
            "routes": len(self.routes),
            "flag_candidates": len(self.flag_candidates),
            "hypotheses": len(self.hypotheses),
            "vulnerabilities": len(self.vulnerabilities),
            "exploit_attempts": len(self.exploit_attempts),
            "sessions": len(self.sessions),
            "evidence": len(self.evidence),
            "executions": len(self.execution_log),
        }
