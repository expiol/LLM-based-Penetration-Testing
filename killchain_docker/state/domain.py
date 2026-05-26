"""Typed facts and evidence carried by RunState."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from killchain_docker.state.common import make_id, utc_now


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

    artifact_id: str = Field(default_factory=lambda: make_id("artifact"))
    path: str
    kind: str = "unknown"
    source: str | None = None
    size: int | None = None
    digest: str | None = None
    preview: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Endpoint(BaseModel):
    """Reachable host/service endpoint used by web, pwn, and exploit workers."""

    model_config = ConfigDict(validate_assignment=True)

    endpoint_id: str = Field(default_factory=lambda: make_id("endpoint"))
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


class Route(BaseModel):
    """HTTP route or page observed during web exploration."""

    model_config = ConfigDict(validate_assignment=True)

    route_id: str = Field(default_factory=lambda: make_id("route"))
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


class FlagCandidate(BaseModel):
    """Flag-like value plus provenance and validation status."""

    model_config = ConfigDict(validate_assignment=True)

    candidate_id: str = Field(default_factory=lambda: make_id("flag-candidate"))
    value: str
    source: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    validated: bool | None = None
    rejected_reason: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class RejectedFlagCandidate(BaseModel):
    """Rejected flag-like value plus the policy reason that rejected it."""

    model_config = ConfigDict(validate_assignment=True)

    rejection_id: str = Field(
        default_factory=lambda: make_id("rejected-flag-candidate")
    )
    value: str
    reason: str
    source: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    rejected_at: datetime = Field(default_factory=utc_now)


class Hypothesis(BaseModel):
    """An analysis or exploit hypothesis with outcome tracking."""

    model_config = ConfigDict(validate_assignment=True)

    hypothesis_id: str = Field(default_factory=lambda: make_id("hypothesis"))
    title: str
    description: str | None = None
    category: str | None = None
    status: str = "open"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class Vulnerability(BaseModel):
    """Security weakness or challenge-specific exploit primitive."""

    model_config = ConfigDict(validate_assignment=True)

    vulnerability_id: str = Field(default_factory=lambda: make_id("vuln"))
    title: str
    severity: Severity = Severity.INFO
    asset_ref: str | None = None
    route_ref: str | None = None
    description: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ExploitAttempt(BaseModel):
    """One concrete exploit or tool experiment and its observed result."""

    model_config = ConfigDict(validate_assignment=True)

    attempt_id: str = Field(default_factory=lambda: make_id("exploit-attempt"))
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


class Session(BaseModel):
    """Authenticated or interactive session state discovered during exploitation."""

    model_config = ConfigDict(validate_assignment=True)

    session_id: str = Field(default_factory=lambda: make_id("session"))
    asset_ref: str | None = None
    endpoint_ref: str | None = None
    username: str | None = None
    session_type: str = "unknown"
    status: str = "active"
    secret_ref: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


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

    evidence_id: str = Field(default_factory=lambda: make_id("evidence"))
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
