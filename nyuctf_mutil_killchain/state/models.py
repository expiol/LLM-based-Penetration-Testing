"""Pydantic models for shared workflow state."""

from __future__ import annotations

from datetime import datetime, timezone
from nyuctf_mutil_killchain.compat import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def _task_id() -> str:
    return f"task-{uuid4().hex[:10]}"


def _run_id() -> str:
    return f"run-{uuid4().hex[:10]}"


def _evidence_id() -> str:
    return f"evidence-{uuid4().hex[:10]}"


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
        if other.mode:
            self.mode = other.mode
        self.request.update(other.request)
        self.result.update(other.result)
        self.extracted.update(other.extracted)
        self.updated_at = utc_now()


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
    evidence_updates: list[EvidenceRecord] = Field(default_factory=list)
    new_tasks: list[Task] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    error_code: TaskErrorCode | None = None
    retryable: bool = True
    solved: bool = False
    validated_flag: str | None = None
    generated_at: datetime = Field(default_factory=utc_now)


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
    evidence: dict[str, EvidenceRecord] = Field(default_factory=dict)
    network_edges: list[NetworkEdge] = Field(default_factory=list)
    task_chain: TaskChain = Field(default_factory=TaskChain)
    execution_log: list[ExecutionRecord] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    solved: bool = False
    validated_flag: str | None = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    last_cycle_at: datetime | None = None

    def touch(self) -> None:
        self.updated_at = utc_now()

    def queue_task(self, task: Task) -> Task:
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
            task.mark_failed(report.error or report.summary, requeue=report.retryable)

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

        self.task_chain.extend(report.new_tasks)
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
            "evidence": len(self.evidence),
            "tasks": len(self.task_chain.tasks),
            "executions": len(self.execution_log),
        }
