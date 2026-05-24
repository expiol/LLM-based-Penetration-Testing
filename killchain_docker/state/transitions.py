"""Run State transition helpers.

RunState stays the durable data Module. This Module owns the mutation policy
for applying worker and tool outputs to that data so invariants have one
place to live.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.models import (
    FlagCandidate,
    StateDelta,
    TodoItem,
    WorkerResult,
)

if TYPE_CHECKING:  # pragma: no cover
    from killchain_docker.state.models import RunState


_NON_DIAGNOSTIC_FAILURE_QUALITIES = frozenset({
    "infrastructure_error",
    "llm_error",
    "llm_schema_validation",
    "metadata_validation",
    "scope_violation_blocked",
})


def apply_state_delta_to_state(state: "RunState", delta: StateDelta) -> None:
    """Apply typed facts from one worker/tool result to RunState."""

    for artifact in delta.artifacts:
        key = artifact.digest or artifact.path
        existing_id = next(
            (
                current_id for current_id, current in state.artifacts.items()
                if (artifact.digest and current.digest == artifact.digest)
                or current.path == artifact.path
            ),
            None,
        )
        if existing_id is not None:
            state.artifacts[existing_id].merge(artifact)
        else:
            artifact.artifact_id = artifact.artifact_id or key
            state.artifacts[artifact.artifact_id] = artifact
    for endpoint in delta.endpoints:
        state.endpoints[endpoint.endpoint_id] = endpoint
    for route in delta.routes:
        state.routes[route.route_id] = route
    for candidate in delta.flag_candidates:
        _apply_flag_candidate(state, candidate)
    for hypothesis in delta.hypotheses:
        state.hypotheses[hypothesis.hypothesis_id] = hypothesis
    for vulnerability in delta.vulnerabilities:
        state.vulnerabilities[vulnerability.vulnerability_id] = vulnerability
    for attempt in delta.exploit_attempts:
        attempt.task_id = attempt.task_id or ""
        state.exploit_attempts[attempt.attempt_id] = attempt
    for session in delta.sessions:
        state.sessions[session.session_id] = session
    state.touch()


def failed_result_has_diagnostic_signal(result: WorkerResult) -> bool:
    """Return true when a failed result still produced useful evidence."""

    if result.success or result.partial or result.retryable:
        return False
    quality = str(result.result_quality or result.output_context.get("failure_kind") or "").strip()
    if quality in _NON_DIAGNOSTIC_FAILURE_QUALITIES:
        return False
    if state_delta_has_signal(result.state_delta):
        return True
    if result.asset_updates or result.finding_updates or result.credential_updates or result.network_updates:
        return True
    ctx = result.output_context or {}
    if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
        return True
    if payload_has_observation(ctx):
        return True
    for evidence in result.evidence_updates:
        if payload_has_observation(evidence.result):
            return True
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        if payload_has_observation(extracted):
            return True
        evidence_ctx = extracted.get("output_context")
        if payload_has_observation(evidence_ctx):
            return True
    return False


def state_delta_has_signal(delta: StateDelta | None) -> bool:
    if delta is None:
        return False
    return bool(
        delta.artifacts
        or delta.endpoints
        or delta.routes
        or delta.flag_candidates
        or delta.hypotheses
        or delta.vulnerabilities
        or delta.exploit_attempts
        or delta.sessions
    )


def payload_has_observation(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in ("stdout", "stderr", "output_text", "raw_log", "stdout_preview", "stderr_preview"):
        if str(payload.get(key) or "").strip():
            return True
    return False


def annotate_result_artifacts(result: WorkerResult) -> None:
    evidence_ids = [
        evidence.evidence_id
        for evidence in result.evidence_updates
        if getattr(evidence, "evidence_id", "")
    ]
    capability = str(result.output_context.get("capability") or "").strip()
    for artifact in result.state_delta.artifacts:
        if evidence_ids:
            existing = artifact.metadata.get("evidence_ids")
            if isinstance(existing, list):
                merged = [str(item) for item in existing if str(item).strip()]
            else:
                merged = []
            for evidence_id in evidence_ids:
                if evidence_id not in merged:
                    merged.append(evidence_id)
            artifact.metadata["evidence_ids"] = merged
        artifact.metadata.setdefault("source_task_id", result.todo_id)
        artifact.metadata.setdefault("source_worker", result.worker_name)
        if capability:
            artifact.metadata.setdefault("source_capability", capability)


def record_todo_execution_context(todo: TodoItem, result: WorkerResult) -> None:
    ctx = result.output_context if isinstance(result.output_context, dict) else {}
    capability = str(ctx.get("capability") or "").strip()
    if capability:
        todo.context.setdefault("executed_capability", capability)

    for key in ("path", "artifact_path", "file_path"):
        value = str(ctx.get(key) or "").strip()
        if value:
            todo.context.setdefault("executed_path", value)
            break

    paths = ctx.get("paths")
    if isinstance(paths, list):
        clean_paths = [str(item).strip() for item in paths if str(item).strip()]
        if clean_paths:
            todo.context.setdefault("executed_paths", clean_paths)


def _apply_flag_candidate(state: "RunState", candidate: FlagCandidate) -> None:
    from killchain_docker.orchestrator.policy import CandidatePolicy

    derived_values: list[str] = []
    decision = CandidatePolicy.decision_for_state(state, candidate.value)
    rejection_reason = candidate.rejected_reason
    if not decision.accepted:
        rejection_reason = decision.reason
        derived_values = CandidatePolicy.derived_candidates_for_state(
            state,
            candidate.value,
        )
    elif candidate.validated is not True and not rejection_reason:
        rejection_reason = state._rejected_flag_reason(candidate.value)
    if candidate.validated is False and not rejection_reason:
        rejection_reason = "candidate_validation_failed"
    if rejection_reason:
        state._reject_flag_candidate(candidate, rejection_reason)
        for derived_value in derived_values:
            if state._rejected_flag_reason(derived_value):
                continue
            derived = FlagCandidate(
                value=derived_value,
                source=f"{candidate.source or 'unknown'}:policy-derived",
                confidence=max(0.1, min(candidate.confidence, 0.45)),
                evidence_refs=list(candidate.evidence_refs),
                metadata={
                    **dict(candidate.metadata),
                    "derived_from_rejected_candidate": candidate.value,
                    "derivation": "expected_prefix_rewrite",
                },
            )
            if CandidatePolicy.decision_for_state(state, derived.value).accepted:
                _upsert_flag_candidate(state, derived)
        return
    _upsert_flag_candidate(state, candidate)


def _upsert_flag_candidate(state: "RunState", candidate: FlagCandidate) -> None:
    existing_id = next(
        (
            current_id for current_id, current in state.flag_candidates.items()
            if current.value == candidate.value
        ),
        None,
    )
    if existing_id is not None:
        state.flag_candidates[existing_id].merge(candidate)
    else:
        state.flag_candidates[candidate.candidate_id] = candidate
