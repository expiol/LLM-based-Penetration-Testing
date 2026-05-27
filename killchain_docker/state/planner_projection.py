"""Planner-specific projections over run state."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING
from killchain_docker.prompt_bounds import bounded_value
from killchain_docker.state.evidence_progress import (
    evidence_ref_can_unlock_progress,
    evidence_ref_supports_exploit_continuation,
)
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.todos import TodoPhase

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


@dataclass(frozen=True)
class PlannerContinuationProjection:
    """Grounding needed to synthesize a planner continuation todo."""

    phase: TodoPhase
    context: dict[str, object]
    dedupe_key: str


class PlannerStateProjection:
    """Read-only facts used by planner context and planner fallback logic."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.metadata = RunMetadataStore(state)

    def knowledge_augmentation(self) -> dict[str, Any]:
        raw = self.metadata.knowledge()
        if not isinstance(raw, dict):
            return {}
        allowed = {
            "enabled",
            "status",
            "hit_count",
            "hint_count",
            "policy",
            "stalled_families",
        }
        metadata = {key: raw[key] for key in allowed if key in raw}
        hints = raw.get("knowledge_hints")
        valid_hints = (
            [hint for hint in hints if isinstance(hint, dict)]
            if isinstance(hints, list)
            else []
        )
        if "hint_count" not in metadata and isinstance(hints, list):
            metadata["hint_count"] = len(valid_hints)
        if metadata.get("policy") == "possibly_misleading":
            suppressed_count = len(valid_hints)
            if not suppressed_count:
                try:
                    suppressed_count = max(0, int(metadata.get("hint_count") or 0))
                except (TypeError, ValueError, OverflowError):
                    suppressed_count = 0
            if suppressed_count:
                metadata["suppressed_hint_count"] = suppressed_count
                metadata["suppressed_reason"] = "knowledge_policy_possibly_misleading"
            return metadata
        if valid_hints:
            metadata["knowledge_hints"] = valid_hints[:3]
        return metadata

    def assets(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "asset_id": asset.asset_id,
                "kind": asset.kind,
                "hostname": asset.hostname,
                "ip_address": asset.ip_address,
                "base_url": asset.base_url,
                "services": [
                    {
                        "port": service.port,
                        "name": service.name,
                        "product": service.product,
                        "version": service.version,
                    }
                    for service in asset.services
                ],
                "tags": sorted(asset.tags),
            }
            for asset in list(self.state.assets.values())[-limit:]
        ]

    def artifacts(self, *, limit: int) -> list[dict[str, Any]]:
        from killchain_docker.prompt_projection import artifact_record

        return [
            artifact_record(artifact)
            for artifact in list(self.state.artifacts.values())[-limit:]
        ]

    def endpoints(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "endpoint_id": endpoint.endpoint_id,
                "asset_ref": endpoint.asset_ref,
                "url": endpoint.url,
                "hostname": endpoint.hostname,
                "port": endpoint.port,
                "protocol": endpoint.protocol,
                "status_code": endpoint.status_code,
                "title": endpoint.title,
                "metadata_preview": str(endpoint.metadata)[:360],
            }
            for endpoint in list(self.state.endpoints.values())[-limit:]
        ]

    def findings(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "description": (finding.description or "")[:360],
                "metadata_preview": str(finding.metadata)[:360],
            }
            for finding in list(self.state.findings.values())[-limit:]
        ]

    def credentials(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "credential_id": credential.credential_id,
                "username": credential.username,
                "credential_type": credential.credential_type,
                "asset_ref": credential.asset_ref,
                "source": credential.source,
                "secret_ref": credential.secret_ref,
                "metadata_preview": str(credential.metadata)[:360],
            }
            for credential in list(self.state.credentials.values())[-limit:]
        ]

    def sessions(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            {
                "session_id": session.session_id,
                "asset_ref": session.asset_ref,
                "endpoint_ref": session.endpoint_ref,
                "username": session.username,
                "session_type": session.session_type,
                "status": session.status,
                "secret_ref": session.secret_ref,
                "metadata_preview": str(session.metadata)[:360],
            }
            for session in list(self.state.sessions.values())[-limit:]
        ]

    def flag_candidates(self, *, limit: int = 12) -> list[dict[str, Any]]:
        return [
            {
                "candidate_id": candidate.candidate_id,
                "value": candidate.value,
                "source": candidate.source,
                "validated": candidate.validated,
            }
            for candidate in list(self.state.flag_candidates.values())[-limit:]
        ]

    def rejected_flag_candidates(self, *, limit: int = 16) -> list[dict[str, Any]]:
        return [
            {
                "value": item.value[:220],
                "reason": item.reason,
                "source": item.source,
                "evidence_refs": item.evidence_refs[-4:],
            }
            for item in self.state.rejected_flag_candidates[-limit:]
        ]

    def round_summaries(self, *, limit: int) -> list[dict[str, Any]]:
        return [
            bounded_value(
                round_record.summary.model_dump(mode="json"),
                width=500,
                list_limit=8,
                dict_limit=10,
            )
            for round_record in self.state.rounds[-limit:]
        ]

    def execution_log(self, *, limit: int) -> list[dict[str, Any]]:
        from killchain_docker.prompt_projection import execution_record

        return [
            execution_record(record) for record in self.state.execution_log[-limit:]
        ]

    def temperature_inputs(self) -> dict[str, int]:
        return {
            "flag_candidates_seen": len(self.state.flag_candidates),
            "rounds_without_flag_candidate": len(self.state.rounds)
            if not self.state.flag_candidates
            else 0,
        }

    def stagnation_base(self) -> dict[str, Any]:
        recent_records = self.state.execution_log[-20:]
        recent_no_candidate_scripts = [
            {
                "task_id": record.task_id,
                "worker_name": record.worker_name,
                "summary": record.summary[:240],
                "error": (record.error or "")[:160],
            }
            for record in recent_records
            if "script execution" in record.summary.lower()
            and "0 flag candidate" in record.summary.lower()
        ]
        return {
            **self.temperature_inputs(),
            "recent_script_no_candidate_count": len(recent_no_candidate_scripts),
            "recent_script_no_candidate_results": recent_no_candidate_scripts[-6:],
        }

    def continuation(self, *, todo_count: int) -> PlannerContinuationProjection | None:
        evidence_ids = [
            evidence_id
            for evidence_id in list(self.state.evidence.keys())[-8:]
            if evidence_ref_can_unlock_progress(self.state, evidence_id)
        ][-3:]
        endpoint_ids = list(self.state.endpoints.keys())[-2:]
        hypothesis_ids = list(self.state.hypotheses.keys())[-2:]
        evidence_count = len(self.state.evidence)
        if not (todo_count or evidence_ids or hypothesis_ids or endpoint_ids):
            return None
        context: dict[str, object] = {
            "family": "execution-continuation",
            "novelty_key": f"continuation:{todo_count}:{evidence_count}",
        }
        if evidence_ids:
            context["evidence_ids"] = evidence_ids
        if endpoint_ids:
            context["endpoint_ids"] = endpoint_ids
        if hypothesis_ids:
            context["hypothesis_ids"] = hypothesis_ids
        phase = (
            TodoPhase.EXPLOIT
            if endpoint_ids
            or any(
                evidence_ref_supports_exploit_continuation(self.state, evidence_id)
                for evidence_id in evidence_ids
            )
            else TodoPhase.ANALYSIS
        )
        return PlannerContinuationProjection(
            phase=phase,
            context=context,
            dedupe_key=f"planner:continuation:{todo_count}:{evidence_count}",
        )

    def empty_retry_available(self, *, todo_count: int) -> bool:
        return bool(todo_count or self.state.evidence or self.state.hypotheses)
