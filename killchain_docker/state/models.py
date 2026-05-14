"""Pydantic models for shared workflow state."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


_PY_ERROR_RE = re.compile(r"^([A-Z]\w+(?:Error|Exception)):\s*(.+)$")


def smart_truncate_code(code: str, *, budget: int = 6000) -> str:
    """Return *code* unchanged when short; otherwise keep head + tail.

    Most generated-script bugs are in either (a) the imports/constants at the top or
    (b) the ``main()`` body at the bottom that parses the challenge file.
    Naive ``code[:budget]`` chops off the bottom, which is exactly where
    header-parsing / output-formatting logic lives.  This helper keeps
    ~55% of the budget at the top and ~45% at the bottom with a marker
    between, so the LLM can always see how its previous attempt opened
    and closed the file.
    """
    if len(code) <= budget:
        return code
    head_budget = int(budget * 0.55)
    tail_budget = budget - head_budget - 40  # 40 reserved for the marker
    omitted = len(code) - head_budget - tail_budget
    marker = f"\n\n# ... [omitted {omitted} chars from middle] ...\n\n"
    return code[:head_budget] + marker + code[-tail_budget:]


def _derive_error_fingerprint(stderr: str, error: str | None) -> str:
    """Return a stable, dedupable fingerprint for a failed worker run.

    Prefers the last Python-style ``XxxError: msg`` line in *stderr*; falls
    back to the last non-empty stderr line (trimmed) or *error*. Used by
    :meth:`GlobalState._record_task_attempt` so the cross-chain memory has
    a meaningful key for dedup.
    """
    if stderr:
        lines = [line.strip() for line in stderr.splitlines() if line.strip()]
        for line in reversed(lines):
            m = _PY_ERROR_RE.match(line)
            if m:
                return f"{m.group(1)}: {m.group(2)}"[:200]
        if lines:
            return lines[-1][:200]
    if error:
        return str(error).strip().splitlines()[0][:200] if str(error).strip() else ""
    return ""


def _task_id() -> str:
    return f"task-{uuid4().hex[:10]}"


def _run_id() -> str:
    return f"run-{uuid4().hex[:10]}"


def _evidence_id() -> str:
    return f"evidence-{uuid4().hex[:10]}"


def _artifact_id() -> str:
    return f"artifact-{uuid4().hex[:10]}"


def _endpoint_id() -> str:
    return f"endpoint-{uuid4().hex[:10]}"


def _route_id() -> str:
    return f"route-{uuid4().hex[:10]}"


def _flag_candidate_id() -> str:
    return f"flag-candidate-{uuid4().hex[:10]}"


def _hypothesis_id() -> str:
    return f"hypothesis-{uuid4().hex[:10]}"


def _vulnerability_id() -> str:
    return f"vuln-{uuid4().hex[:10]}"


def _exploit_attempt_id() -> str:
    return f"exploit-attempt-{uuid4().hex[:10]}"


def _session_id() -> str:
    return f"session-{uuid4().hex[:10]}"


def _severity_rank(value: "Severity") -> int:
    order = {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    return order[value]


class TaskStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    CANCELLED = "cancelled"


class RunStatus(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    SOLVED = "solved"
    FAILED = "failed"
    STOPPED = "stopped"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskErrorCode(StrEnum):
    """Machine-readable error classification for task failures."""

    MISSING_REQUIRED_CONTEXT = "missing_required_context"
    INVALID_TASK_TYPE = "invalid_task_type"
    TASK_CONTEXT_CONFLICT = "task_context_conflict"
    UNKNOWN_ASSET_ID = "unknown_asset_id"
    AMBIGUOUS_ASSET_MATCH = "ambiguous_asset_match"
    RETRY_LIMIT_REACHED = "retry_limit_reached"
    REPAIR_FAILED = "repair_failed"
    DISPATCH_REFUSED = "dispatch_refused"
    WORKER_PRECONDITION_FAILED = "worker_precondition_failed"
    WORKER_LLM_ERROR = "worker_llm_error"


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


# Centralised list of `input_context` keys that the worker layer expects to be
# scalars (single string/int) vs lists.  When the LLM planner emits a list
# where a scalar is expected (or vice versa), the worker would normally crash
# with ``AttributeError`` deep inside (e.g. recon-agent calling ``urlparse``
# on a list).  We normalise once at task creation so no worker has to defend
# against type drift.
_TASK_INPUT_SCALAR_KEYS: frozenset[str] = frozenset({
    "scope", "candidate_flag", "asset_id", "hostname", "base_url",
    "target", "analysis_kind", "page_url", "files_root",
})
_TASK_INPUT_LIST_KEYS: frozenset[str] = frozenset({
    "source_files", "binary_files", "archive_files", "database_files",
    "pcap_files", "repo_paths", "ports", "paths", "forms",
    "credential_ids", "focus_asset_ids", "seed_terms", "previous_attempts",
    "challenge_files", "must_avoid", "required_checks",
})


def _coerce_scalar(value: Any) -> Any:
    """Take the first non-empty entry of a list; otherwise return as-is."""
    if isinstance(value, (list, tuple)):
        for entry in value:
            if entry not in (None, "", [], {}, ()):
                return entry
        return None
    return value


def _coerce_list(value: Any) -> Any:
    """Wrap a scalar in a list; split a comma-separated string; otherwise return as-is."""
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str) and "," in value:
        return [part.strip() for part in value.split(",") if part.strip()]
    return [value]


class Task(BaseModel):
    """Single unit of work managed by the orchestrator."""

    model_config = ConfigDict(validate_assignment=True)

    task_id: str = Field(default_factory=_task_id)
    title: str
    description: str
    task_type: str
    priority: int = Field(default=50, ge=0, le=100)
    status: TaskStatus = TaskStatus.PENDING
    dependencies: list[str] = Field(default_factory=list)
    assigned_worker: str | None = None
    input_context: dict[str, Any] = Field(default_factory=dict)
    output_context: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    dedupe_key: str | None = None
    attempts: int = 0
    max_attempts: int = Field(default=3, ge=1)
    last_error: str | None = None
    error_code: TaskErrorCode | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    def model_post_init(self, __context: Any) -> None:
        """Normalise ``input_context`` field types after construction."""
        self.normalise_input_context()

    def normalise_input_context(self) -> None:
        """Coerce known scalar/list keys to their expected shapes in place.

        Defends against LLM-emitted shape drift (e.g. ``scope=["http://x"]``
        when the worker expects ``scope="http://x"``).  Idempotent.
        """
        ctx = self.input_context
        if not isinstance(ctx, dict):
            return
        for key in _TASK_INPUT_SCALAR_KEYS & ctx.keys():
            ctx[key] = _coerce_scalar(ctx[key])
        for key in _TASK_INPUT_LIST_KEYS & ctx.keys():
            ctx[key] = _coerce_list(ctx[key])

    def is_ready(self, completed_task_ids: set[str]) -> bool:
        return self.status == TaskStatus.PENDING and set(self.dependencies).issubset(completed_task_ids)

    def mark_running(self, worker_name: str) -> None:
        self.status = TaskStatus.RUNNING
        self.assigned_worker = worker_name
        self.attempts += 1
        self.last_error = None
        self.error_code = None
        self.updated_at = utc_now()

    def mark_completed(self, output_context: dict[str, Any] | None = None) -> None:
        self.status = TaskStatus.COMPLETED
        if output_context:
            self.output_context.update(output_context)
        self.updated_at = utc_now()

    def mark_failed(
        self, error: str, *, requeue: bool = False, error_code: TaskErrorCode | None = None,
    ) -> None:
        self.last_error = error
        self.error_code = error_code
        if requeue and self.attempts < self.max_attempts:
            self.status = TaskStatus.PENDING
        else:
            self.status = TaskStatus.FAILED
        self.updated_at = utc_now()

    def mark_blocked(
        self, reason: str, *, error_code: TaskErrorCode | None = None,
    ) -> None:
        self.status = TaskStatus.BLOCKED
        self.last_error = reason
        self.error_code = error_code
        self.updated_at = utc_now()


class TaskChain(BaseModel):
    """Mutable queue of tasks with deterministic selection helpers."""

    model_config = ConfigDict(validate_assignment=True)

    tasks: list[Task] = Field(default_factory=list)
    version: int = 1
    updated_at: datetime = Field(default_factory=utc_now)

    def _bump_version(self) -> None:
        self.version += 1
        self.updated_at = utc_now()

    def get(self, task_id: str) -> Task | None:
        return next((task for task in self.tasks if task.task_id == task_id), None)

    def find_by_dedupe_key(self, dedupe_key: str) -> Task | None:
        return next((task for task in self.tasks if task.dedupe_key == dedupe_key), None)

    def completed_task_ids(self) -> set[str]:
        return {task.task_id for task in self.tasks if task.status == TaskStatus.COMPLETED}

    def add_task(self, task: Task) -> Task:
        if task.dedupe_key:
            existing = next(
                (
                    item
                    for item in self.tasks
                    if item.dedupe_key == task.dedupe_key
                    and item.status not in {TaskStatus.FAILED, TaskStatus.CANCELLED}
                ),
                None,
            )
            if existing is not None:
                return existing

        self.tasks.append(task)
        self._bump_version()
        return task

    def extend(self, tasks: list[Task]) -> list[Task]:
        added: list[Task] = []
        for task in tasks:
            added.append(self.add_task(task))
        return added

    def next_ready_task(self) -> Task | None:
        completed = self.completed_task_ids()
        ready = [task for task in self.tasks if task.is_ready(completed)]
        ready.sort(key=lambda task: (-task.priority, task.created_at))
        return ready[0] if ready else None

    def ready_tasks(self) -> list[Task]:
        """Return ready tasks in queue order for planner-owned dispatch."""
        completed = self.completed_task_ids()
        return [task for task in self.tasks if task.is_ready(completed)]

    def has_open_tasks(self) -> bool:
        return any(
            task.status in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.BLOCKED}
            for task in self.tasks
        )


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


class PlannerSignal(BaseModel):
    """Worker-to-planner signal that may inform later task generation."""

    source_task_id: str | None = None
    worker_name: str | None = None
    summary: str
    suggested_task_type: str | None = None
    suggested_input_context: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    failure_reason: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class WorkerReport(BaseModel):
    """Structured response returned by a worker agent."""

    task_id: str
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
    planner_signals: list[PlannerSignal] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    error_code: TaskErrorCode | None = None
    retryable: bool = True
    solved: bool = False
    validated_flag: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)


#: Per-task-type memory of the last K failed attempts. Used by LLM-driven
#: workers to seed ``previous_attempts`` on freshly-planned tasks so a new
#: chain doesn't forget what the previous chain just tried. Bounded to keep
#: state.json from growing unbounded on long runs.
TASK_TYPE_MEMORY_LIMIT = 8

#: FIFO caps applied at write time inside :meth:`GlobalState.apply_worker_report`
#: so a long batch run cannot bloat ``state.json`` past hundreds of MB.  Caps
#: are deliberately generous (planner serialization trims further when feeding
#: LLM prompts); they only bound disk/RAM growth, not what the LLM sees.
EXECUTION_LOG_LIMIT = 500
NOTES_LIMIT = 500
ORCHESTRATION_NOTES_LIMIT = 500
EVIDENCE_DICT_LIMIT = 800
TYPED_FACT_DICT_LIMIT = 800
PLANNER_SIGNAL_LIMIT = 200

# Queue fan-out guards.  These only cap still-open backlog; completed history
# remains available for reporting while pathological planner/worker follow-up
# loops cannot fill the queue with hundreds of equivalent probes.
PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET = 12
PENDING_WEB_PATH_PROBE_LIMIT_PER_ASSET = 8
PENDING_WEB_CONTENT_LIMIT_PER_ASSET = 16
PENDING_EXPLOIT_HYPOTHESIS_LIMIT = 8
PENDING_FLAG_VALIDATE_LIMIT = 20


class TaskAttemptMemory(BaseModel):
    """Snapshot of a single failed task attempt, indexed by task_type.

    Captures only the LLM-relevant slice of the worker report: the summary
    that surfaces the failure fingerprint, short stdout/stderr previews,
    and any script/code preview when present.
    """

    task_id: str
    title: str
    worker_name: str
    summary: str
    error: str | None = None
    stdout_preview: str = ""
    stderr_preview: str = ""
    script_code_preview: str = ""
    error_fingerprint: str = ""
    recorded_at: datetime = Field(default_factory=utc_now)


class RunMemory(BaseModel):
    """Bounded planner-facing memory folded from prior execution evidence."""

    long_term_summary: str = ""
    confirmed_facts: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    dead_ends: list[str] = Field(default_factory=list)
    current_focus: str = ""
    last_updated_at: datetime | None = None


class GlobalState(BaseModel):
    """System-wide shared memory updated after every worker execution."""

    model_config = ConfigDict(validate_assignment=True)

    run_id: str = Field(default_factory=_run_id)
    objective: str
    authorized_scope: list[str] = Field(default_factory=list)
    status: RunStatus = RunStatus.IDLE
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
    task_chain: TaskChain = Field(default_factory=TaskChain)
    execution_log: list[ExecutionRecord] = Field(default_factory=list)
    run_memory: RunMemory = Field(default_factory=RunMemory)
    planner_signals: list[PlannerSignal] = Field(default_factory=list)
    task_type_memory: dict[str, list[TaskAttemptMemory]] = Field(
        default_factory=dict
    )
    #: Worker-emitted notes (free-form context lines from
    #: :attr:`WorkerReport.notes`).  Read by sibling workers via
    #: ``recent_notes`` slices to share lightweight worker-to-worker hints.
    notes: list[str] = Field(default_factory=list)
    #: Orchestrator / planner / dispatch / recovery messages (queue empty
    #: hints, LLM error notes, dispatch refusals, …).  Persisted to
    #: ``state.json`` and ``report.md`` but **not** fed back into worker
    #: prompts, so internal chatter does not contaminate downstream LLM
    #: reasoning.
    orchestration_notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    solved: bool = False
    validated_flag: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_cycle_at: datetime | None = None

    def touch(self) -> None:
        self.updated_at = utc_now()
        self._enforce_caps()

    def _enforce_caps(self) -> None:
        """Trim unbounded collections to their FIFO write-end caps.

        Runs on every state write so disk/RAM growth stays bounded even when
        external callers (orchestrator loop, recovery policy, dispatch policy)
        append to ``notes`` / ``execution_log`` outside ``apply_worker_report``.
        """
        if len(self.execution_log) > EXECUTION_LOG_LIMIT:
            del self.execution_log[: len(self.execution_log) - EXECUTION_LOG_LIMIT]
        if len(self.notes) > NOTES_LIMIT:
            del self.notes[: len(self.notes) - NOTES_LIMIT]
        if len(self.orchestration_notes) > ORCHESTRATION_NOTES_LIMIT:
            del self.orchestration_notes[
                : len(self.orchestration_notes) - ORCHESTRATION_NOTES_LIMIT
            ]
        if len(self.planner_signals) > PLANNER_SIGNAL_LIMIT:
            del self.planner_signals[: len(self.planner_signals) - PLANNER_SIGNAL_LIMIT]
        if len(self.evidence) > EVIDENCE_DICT_LIMIT:
            # Insertion-order eviction; in Python 3.7+ dicts preserve order so
            # this is roughly oldest-first by creation.
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

    def _queue_guard_existing_task(self, task: Task) -> Task | None:
        """Return an existing open task when adding *task* would fan out."""

        if task.task_type == "web.form_probe":
            asset_id = str(task.input_context.get("asset_id") or "")
            pending = [
                item for item in self.task_chain.tasks
                if item.task_type == "web.form_probe"
                and item.status == TaskStatus.PENDING
                and str(item.input_context.get("asset_id") or "") == asset_id
            ]
            if len(pending) >= PENDING_WEB_FORM_PROBE_LIMIT_PER_ASSET:
                return pending[0]

        if task.task_type == "web.path_probe":
            asset_id = str(task.input_context.get("asset_id") or "")
            pending = [
                item for item in self.task_chain.tasks
                if item.task_type == "web.path_probe"
                and item.status == TaskStatus.PENDING
                and str(item.input_context.get("asset_id") or "") == asset_id
            ]
            if len(pending) >= PENDING_WEB_PATH_PROBE_LIMIT_PER_ASSET:
                return pending[0]

        if task.task_type == "web.content_review":
            asset_id = str(task.input_context.get("asset_id") or "")
            pending = [
                item for item in self.task_chain.tasks
                if item.task_type == "web.content_review"
                and item.status == TaskStatus.PENDING
                and str(item.input_context.get("asset_id") or "") == asset_id
            ]
            if len(pending) >= PENDING_WEB_CONTENT_LIMIT_PER_ASSET:
                return pending[0]

        if task.task_type == "exploit.hypothesis":
            pending = [
                item for item in self.task_chain.tasks
                if item.task_type == "exploit.hypothesis"
                and item.status == TaskStatus.PENDING
            ]
            if len(pending) >= PENDING_EXPLOIT_HYPOTHESIS_LIMIT:
                return pending[0]

        if task.task_type == "flag.validate":
            pending = [
                item for item in self.task_chain.tasks
                if item.task_type == "flag.validate"
                and item.status == TaskStatus.PENDING
            ]
            if len(pending) >= PENDING_FLAG_VALIDATE_LIMIT:
                return pending[0]

        return None

    def queue_task(self, task: Task) -> Task:
        guarded = self._queue_guard_existing_task(task)
        if guarded is not None:
            self.touch()
            return guarded
        queued = self.task_chain.add_task(task)
        self.touch()
        return queued

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

    def upsert_artifact(self, artifact: Artifact) -> None:
        key = artifact.digest or artifact.path
        existing_id = next(
            (
                current_id
                for current_id, current in self.artifacts.items()
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
        self.touch()

    def upsert_endpoint(self, endpoint: Endpoint) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.endpoints.items()
                if (endpoint.url and current.url == endpoint.url)
                or (
                    endpoint.hostname
                    and current.hostname == endpoint.hostname
                    and current.port == endpoint.port
                    and current.protocol == endpoint.protocol
                )
            ),
            None,
        )
        if existing_id is not None:
            self.endpoints[existing_id].merge(endpoint)
        else:
            self.endpoints[endpoint.endpoint_id] = endpoint
        self.touch()

    def upsert_route(self, route: Route) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.routes.items()
                if current.url == route.url
                and current.method.upper() == route.method.upper()
            ),
            None,
        )
        if existing_id is not None:
            self.routes[existing_id].merge(route)
        else:
            self.routes[route.route_id] = route
        self.touch()

    def upsert_flag_candidate(self, candidate: FlagCandidate) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.flag_candidates.items()
                if current.value == candidate.value
            ),
            None,
        )
        if existing_id is not None:
            self.flag_candidates[existing_id].merge(candidate)
        else:
            self.flag_candidates[candidate.candidate_id] = candidate
        self.touch()

    def upsert_hypothesis(self, hypothesis: Hypothesis) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.hypotheses.items()
                if current.title == hypothesis.title
                and (current.category or "") == (hypothesis.category or "")
            ),
            None,
        )
        if existing_id is not None:
            self.hypotheses[existing_id].merge(hypothesis)
        else:
            self.hypotheses[hypothesis.hypothesis_id] = hypothesis
        self.touch()

    def upsert_vulnerability(self, vulnerability: Vulnerability) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.vulnerabilities.items()
                if current.title == vulnerability.title
                and (current.asset_ref or "") == (vulnerability.asset_ref or "")
                and (current.route_ref or "") == (vulnerability.route_ref or "")
            ),
            None,
        )
        if existing_id is not None:
            self.vulnerabilities[existing_id].merge(vulnerability)
        else:
            self.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
        self.touch()

    def upsert_exploit_attempt(self, attempt: ExploitAttempt) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.exploit_attempts.items()
                if attempt.task_id
                and current.task_id == attempt.task_id
                and current.worker_name == attempt.worker_name
            ),
            None,
        )
        if existing_id is not None:
            self.exploit_attempts[existing_id].merge(attempt)
        else:
            self.exploit_attempts[attempt.attempt_id] = attempt
        self.touch()

    def upsert_session(self, session: Session) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.sessions.items()
                if current.asset_ref == session.asset_ref
                and current.endpoint_ref == session.endpoint_ref
                and current.username == session.username
                and current.session_type == session.session_type
            ),
            None,
        )
        if existing_id is not None:
            self.sessions[existing_id].merge(session)
        else:
            self.sessions[session.session_id] = session
        self.touch()

    def apply_state_delta(self, delta: StateDelta) -> None:
        for artifact in delta.artifacts:
            self.upsert_artifact(artifact)
        for endpoint in delta.endpoints:
            self.upsert_endpoint(endpoint)
        for route in delta.routes:
            self.upsert_route(route)
        for candidate in delta.flag_candidates:
            self.upsert_flag_candidate(candidate)
        for hypothesis in delta.hypotheses:
            self.upsert_hypothesis(hypothesis)
        for vulnerability in delta.vulnerabilities:
            self.upsert_vulnerability(vulnerability)
        for attempt in delta.exploit_attempts:
            self.upsert_exploit_attempt(attempt)
        for session in delta.sessions:
            self.upsert_session(session)

    def add_network_edge(self, edge: NetworkEdge) -> None:
        exists = any(
            current.source == edge.source
            and current.target == edge.target
            and current.relationship == edge.relationship
            for current in self.network_edges
        )
        if not exists:
            self.network_edges.append(edge)
            self.touch()

    def apply_worker_report(self, report: WorkerReport) -> None:
        task = self.task_chain.get(report.task_id)
        if task is None:
            raise KeyError(f"Unknown task id: {report.task_id}")

        if report.success:
            task.mark_completed(report.output_context)
        else:
            task.mark_failed(
                report.error or report.summary,
                requeue=report.retryable,
                error_code=report.error_code,
            )
            self._record_task_attempt(task, report)

        for asset in report.asset_updates:
            self.upsert_asset(asset)
        for finding in report.finding_updates:
            self.upsert_finding(finding)
        for credential in report.credential_updates:
            self.upsert_credential(credential)
        for evidence in report.evidence_updates:
            self.upsert_evidence(evidence)
        for edge in report.network_updates:
            self.add_network_edge(edge)
        self.apply_state_delta(report.state_delta)

        for signal in report.planner_signals:
            if signal.source_task_id is None:
                signal.source_task_id = report.task_id
            if signal.worker_name is None:
                signal.worker_name = report.worker_name
            self.planner_signals.append(signal)

        if report.solved:
            self.solved = True
        if report.validated_flag:
            self.validated_flag = report.validated_flag
        self.execution_log.append(
            ExecutionRecord(
                task_id=report.task_id,
                worker_name=report.worker_name,
                success=report.success,
                summary=report.summary,
                error=report.error,
            )
        )
        self.notes.extend(report.notes)
        self.touch()

    def recent_attempt_memory_for(
        self,
        task_type: str,
        *,
        limit: int = 5,
    ) -> list[TaskAttemptMemory]:
        """Return up to *limit* deduped :class:`TaskAttemptMemory` entries.

        Walks ``task_type_memory[task_type]`` newest→oldest, keeps **one
        entry per non-empty ``error_fingerprint``** (so long-tail failure
        modes are not pushed out of a small window by recent retries),
        then returns oldest→newest.  Empty-fingerprint entries are always
        kept since they convey distinct information.

        Used by workers and planner prompts so dedup semantics stay consistent.
        """
        memory = self.task_type_memory.get(task_type) or []
        seen_fp: set[str] = set()
        picked: list[TaskAttemptMemory] = []
        for entry in reversed(memory):
            fp = (entry.error_fingerprint or "").strip()
            if fp and fp in seen_fp:
                continue
            if fp:
                seen_fp.add(fp)
            picked.append(entry)
            if len(picked) >= max(1, limit):
                break
        picked.reverse()
        return picked

    def fingerprint_counts_for(
        self,
        task_type: str,
    ) -> dict[str, int]:
        """Return ``{fingerprint: occurrences}`` across cross-chain memory.

        Critical for downstream prompts: without this, dedup hides the
        fact that the LLM has produced *the same garbled output N times*
        — and the prompt builder cannot warn the LLM to switch strategy.
        Empty fingerprints are skipped.
        """
        counts: dict[str, int] = {}
        for entry in self.task_type_memory.get(task_type) or []:
            fp = (entry.error_fingerprint or "").strip()
            if not fp:
                continue
            counts[fp] = counts.get(fp, 0) + 1
        return counts

    def recent_attempts_for(
        self,
        task_type: str,
        *,
        limit: int = 5,
    ) -> list[dict[str, Any]]:
        """Return deduped failed-attempt snapshots shaped like ``previous_attempts``.

        See :meth:`recent_attempt_memory_for` for the dedup contract; this
        helper just renders each picked entry as the dict shape that worker
        prompts consume. Each entry also carries an
        ``occurrences`` count so consumers can warn the LLM when it has
        re-produced the same garbled output multiple times.
        """
        counts = self.fingerprint_counts_for(task_type)
        attempts: list[dict[str, Any]] = []
        for entry in self.recent_attempt_memory_for(task_type, limit=limit):
            fp = (entry.error_fingerprint or "").strip()
            attempts.append(
                {
                    "attempt": 0,
                    "task_id": entry.task_id,
                    "title": entry.title,
                    "worker_name": entry.worker_name,
                    "summary": entry.summary,
                    "error": entry.error,
                    "stdout": entry.stdout_preview,
                    "stderr": entry.stderr_preview,
                    "script_code_preview": entry.script_code_preview,
                    "error_fingerprint": entry.error_fingerprint,
                    "occurrences": counts.get(fp, 1),
                    "source": "cross_chain_memory",
                }
            )
        return attempts

    def _record_task_attempt(self, task: Task, report: WorkerReport) -> None:
        """Append a :class:`TaskAttemptMemory` entry for failed *report*.

        Stored under ``self.task_type_memory[task.task_type]``, capped at
        :data:`TASK_TYPE_MEMORY_LIMIT` entries (FIFO) so freshly-planned
        tasks of the same type can read what previous chains tried.
        """
        ctx = report.output_context or {}
        stdout_preview = str(ctx.get("stdout", ""))[:1500]
        stderr_preview = str(ctx.get("stderr", ""))[:1500]
        # Smart-truncate so we don't lose the (often-critical) tail of the
        # script when it overflows the budget.
        script_code_preview = smart_truncate_code(
            str(
                ctx.get("script_code_preview")
                or ""
            ),
            budget=6000,
        )

        # Prefer a worker-classified fingerprint when present; fall back to the
        # generic stderr/error derivation only when the worker did not classify
        # the failure itself.
        reported_fp = str(ctx.get("error_fingerprint") or "").strip()[:200]
        fingerprint = reported_fp or _derive_error_fingerprint(
            stderr_preview, report.error
        )

        snapshot = TaskAttemptMemory(
            task_id=task.task_id,
            title=task.title,
            worker_name=report.worker_name,
            summary=report.summary,
            error=report.error,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            script_code_preview=script_code_preview,
            error_fingerprint=fingerprint,
        )
        memory = self.task_type_memory.setdefault(task.task_type, [])
        memory.append(snapshot)
        # FIFO trim so state.json stays bounded.
        if len(memory) > TASK_TYPE_MEMORY_LIMIT:
            del memory[: len(memory) - TASK_TYPE_MEMORY_LIMIT]
        # Re-assign so pydantic validate_assignment picks up the change.
        self.task_type_memory[task.task_type] = memory
        self.touch()

    def infer_asset_identity(self, ctx: dict[str, Any]) -> dict[str, str]:
        """Fill missing asset_id / base_url / hostname / ports from discovered assets.

        When exactly one asset exists, inference is unambiguous.  When multiple
        assets exist, only infer if ``ctx["asset_id"]`` already matches a known
        asset.  Returns a dict of ``{field_name: filled_value}`` for logging.
        """
        assets = self.assets
        if not assets:
            return {}

        filled: dict[str, str] = {}
        asset_id = ctx.get("asset_id")

        if asset_id and asset_id in assets:
            asset = assets[asset_id]
            if not ctx.get("base_url") and asset.base_url:
                ctx["base_url"] = asset.base_url
                filled["base_url"] = asset.base_url
            if not ctx.get("hostname") and asset.hostname:
                ctx["hostname"] = asset.hostname
                filled["hostname"] = asset.hostname
            if not ctx.get("ports") and asset.services:
                ctx["ports"] = [s.port for s in asset.services]
                filled["ports"] = str(ctx["ports"])
            return filled

        if len(assets) == 1:
            only_asset = next(iter(assets.values()))
            if not ctx.get("asset_id"):
                ctx.setdefault("asset_id", only_asset.asset_id)
                filled["asset_id"] = only_asset.asset_id
            if not ctx.get("base_url") and only_asset.base_url:
                ctx["base_url"] = only_asset.base_url
                filled["base_url"] = only_asset.base_url
            if not ctx.get("hostname") and only_asset.hostname:
                ctx["hostname"] = only_asset.hostname
                filled["hostname"] = only_asset.hostname
            if not ctx.get("ports") and only_asset.services:
                ctx["ports"] = [s.port for s in only_asset.services]
                filled["ports"] = str(ctx["ports"])

        return filled

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "solved": self.solved,
            "validated_flag": self.validated_flag,
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
            "tasks": len(self.task_chain.tasks),
            "executions": len(self.execution_log),
            "planner_signals": len(self.planner_signals),
            "run_memory": self.run_memory.model_dump(mode="json"),
        }


def _todo_id() -> str:
    return f"todo-{uuid4().hex[:10]}"


def _assignment_id() -> str:
    return f"assignment-{uuid4().hex[:10]}"


def _round_id() -> str:
    return f"round-{uuid4().hex[:10]}"


class TodoStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class TodoItem(BaseModel):
    """High-level planner task consumed by the router and persona workers."""

    model_config = ConfigDict(validate_assignment=True)

    todo_id: str = Field(default_factory=_todo_id)
    goal: str
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
    solved: bool = False
    validated_flag: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)


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
    notes: list[str] = Field(default_factory=list)
    orchestration_notes: list[str] = Field(default_factory=list)
    solved: bool = False
    validated_flag: str | None = None
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
                and item.status in {TodoStatus.PENDING, TodoStatus.RUNNING, TodoStatus.COMPLETED}
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
        if result.success:
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
        context = todo.context or {}
        important = [
            str(context.get(key) or "")
            for key in (
                "scope", "files_root", "asset_id", "base_url", "hostname",
                "candidate_flag", "analysis_kind",
            )
            if context.get(key)
        ]
        for list_key in (
            "source_files", "binary_files", "archive_files", "database_files",
            "pcap_files", "repo_paths", "paths", "seed_terms",
        ):
            values = context.get(list_key)
            if isinstance(values, list) and values:
                important.append(",".join(str(item) for item in values[:8]))
        tail = ":".join(important) if important else todo.goal[:80]
        return f"todo:{tail}"

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "status": self.status,
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
