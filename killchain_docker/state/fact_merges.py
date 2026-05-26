"""Merge policy for typed durable facts."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.common import utc_now
from killchain_docker.state.domain import AssetKind, Severity

if TYPE_CHECKING:
    from killchain_docker.state.domain import (
        Asset,
        Artifact,
        Credential,
        Endpoint,
        EvidenceRecord,
        ExploitAttempt,
        Finding,
        FlagCandidate,
        Hypothesis,
        Route,
        Service,
        Session,
        Vulnerability,
    )

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_rank(value: Severity | str) -> int:
    try:
        severity = Severity(value)
    except ValueError:
        return 0
    return _SEVERITY_RANK[severity]


def merge_service(existing: "Service", incoming: "Service") -> None:
    if incoming.name:
        existing.name = incoming.name
    if incoming.product:
        existing.product = incoming.product
    if incoming.version:
        existing.version = incoming.version


def merge_asset(existing: "Asset", incoming: "Asset") -> None:
    if existing.kind == AssetKind.UNKNOWN and incoming.kind != AssetKind.UNKNOWN:
        existing.kind = incoming.kind
    if incoming.hostname:
        existing.hostname = incoming.hostname
    if incoming.ip_address:
        existing.ip_address = incoming.ip_address
    if incoming.base_url:
        existing.base_url = incoming.base_url
    existing.tags |= incoming.tags
    existing.metadata.update(incoming.metadata)
    services = {
        (service.port, service.protocol): service for service in existing.services
    }
    for service in incoming.services:
        key = (service.port, service.protocol)
        if key in services:
            merge_service(services[key], service)
        else:
            existing.services.append(service)
    existing.updated_at = utc_now()


def merge_finding(existing: "Finding", incoming: "Finding") -> None:
    if severity_rank(incoming.severity) > severity_rank(existing.severity):
        existing.severity = incoming.severity
    if incoming.description:
        existing.description = incoming.description
    existing.asset_refs = sorted(set(existing.asset_refs) | set(incoming.asset_refs))
    existing.evidence_refs = sorted(
        set(existing.evidence_refs) | set(incoming.evidence_refs)
    )
    existing.metadata.update(incoming.metadata)
    if incoming.status:
        existing.status = incoming.status
    existing.updated_at = utc_now()


def merge_credential(existing: "Credential", incoming: "Credential") -> None:
    if incoming.asset_ref:
        existing.asset_ref = incoming.asset_ref
    if incoming.source:
        existing.source = incoming.source
    if incoming.secret_ref:
        existing.secret_ref = incoming.secret_ref
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_evidence(existing: "EvidenceRecord", incoming: "EvidenceRecord") -> None:
    if incoming.summary:
        existing.summary = incoming.summary
    if incoming.parser_name:
        existing.parser_name = incoming.parser_name
    if incoming.capability:
        existing.capability = incoming.capability
    if incoming.mode:
        existing.mode = incoming.mode
    existing.request.update(incoming.request)
    existing.result.update(incoming.result)
    existing.extracted.update(incoming.extracted)
    existing.updated_at = utc_now()


def merge_flag_candidate(existing: "FlagCandidate", incoming: "FlagCandidate") -> None:
    if incoming.source:
        existing.source = incoming.source
    existing.confidence = max(existing.confidence, incoming.confidence)
    if incoming.validated is not None:
        existing.validated = incoming.validated
    if incoming.rejected_reason:
        existing.rejected_reason = incoming.rejected_reason
    existing.evidence_refs = sorted(
        set(existing.evidence_refs) | set(incoming.evidence_refs)
    )
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_artifact(existing: "Artifact", incoming: "Artifact") -> None:
    if incoming.kind and existing.kind == "unknown":
        existing.kind = incoming.kind
    if incoming.source:
        existing.source = incoming.source
    if incoming.size is not None:
        existing.size = incoming.size
    if incoming.digest:
        existing.digest = incoming.digest
    if incoming.preview:
        existing.preview = incoming.preview
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_endpoint(existing: "Endpoint", incoming: "Endpoint") -> None:
    for field_name in ("asset_ref", "url", "hostname", "protocol", "title"):
        value = getattr(incoming, field_name)
        if value:
            setattr(existing, field_name, value)
    if incoming.port is not None:
        existing.port = incoming.port
    if incoming.status_code is not None:
        existing.status_code = incoming.status_code
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_route(existing: "Route", incoming: "Route") -> None:
    for field_name in ("endpoint_ref", "asset_ref", "url", "path", "method", "source"):
        value = getattr(incoming, field_name)
        if value:
            setattr(existing, field_name, value)
    if incoming.status_code is not None:
        existing.status_code = incoming.status_code
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_hypothesis(existing: "Hypothesis", incoming: "Hypothesis") -> None:
    if incoming.description:
        existing.description = incoming.description
    if incoming.category:
        existing.category = incoming.category
    if incoming.status:
        existing.status = incoming.status
    existing.confidence = max(existing.confidence, incoming.confidence)
    existing.evidence_refs = sorted(
        set(existing.evidence_refs) | set(incoming.evidence_refs)
    )
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_vulnerability(existing: "Vulnerability", incoming: "Vulnerability") -> None:
    if severity_rank(incoming.severity) > severity_rank(existing.severity):
        existing.severity = incoming.severity
    for field_name in ("asset_ref", "route_ref", "description"):
        value = getattr(incoming, field_name)
        if value:
            setattr(existing, field_name, value)
    existing.evidence_refs = sorted(
        set(existing.evidence_refs) | set(incoming.evidence_refs)
    )
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_exploit_attempt(
    existing: "ExploitAttempt", incoming: "ExploitAttempt"
) -> None:
    for field_name in ("task_id", "worker_name", "target_ref", "technique", "summary"):
        value = getattr(incoming, field_name)
        if value:
            setattr(existing, field_name, value)
    existing.success = existing.success or incoming.success
    existing.flag_candidate_refs = sorted(
        set(existing.flag_candidate_refs) | set(incoming.flag_candidate_refs)
    )
    existing.evidence_refs = sorted(
        set(existing.evidence_refs) | set(incoming.evidence_refs)
    )
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()


def merge_session(existing: "Session", incoming: "Session") -> None:
    for field_name in (
        "asset_ref",
        "endpoint_ref",
        "username",
        "session_type",
        "status",
        "secret_ref",
    ):
        value = getattr(incoming, field_name)
        if value:
            setattr(existing, field_name, value)
    existing.metadata.update(incoming.metadata)
    existing.updated_at = utc_now()
