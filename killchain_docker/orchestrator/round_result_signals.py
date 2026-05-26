"""Signals extracted from individual worker results."""

from __future__ import annotations

from killchain_docker.state.todos import WorkerResult

NO_PROGRESS_QUALITIES = frozenset(
    {
        "connection_refused",
        "connection_reset",
        "empty_result",
        "metadata_validation",
        "network_incomplete_read",
        "network_pipe_closed",
        "no_candidate",
        "package_install_blocked",
        "partial_no_candidate",
        "scope_violation_blocked",
        "timeout",
        "unbounded_loop_guard",
    }
)
NEAR_MISS_QUALITIES = frozenset({"near_miss"})


def has_observation_text(payload: dict[str, object]) -> bool:
    for key in ("stdout", "stderr", "output_text", "raw_log"):
        if str(payload.get(key) or "").strip():
            return True
    return False


def quality_tokens(result: WorkerResult) -> set[str]:
    tokens = {str(result.result_quality or "").strip().lower()}
    ctx = result.output_context or {}
    for key in ("failure_kind", "partial_reason", "result_quality"):
        value = ctx.get(key)
        if value:
            tokens.add(str(value).strip().lower())
    for evidence in result.evidence_updates:
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        evidence_ctx = extracted.get("output_context")
        if isinstance(evidence_ctx, dict):
            for key in ("failure_kind", "partial_reason", "result_quality"):
                value = evidence_ctx.get(key)
                if value:
                    tokens.add(str(value).strip().lower())
    tokens.discard("")
    return tokens


def has_near_miss_signal(result: WorkerResult) -> bool:
    ctx = result.output_context or {}
    if ctx.get("near_miss_candidates") or ctx.get("flag_candidates"):
        return True
    if quality_tokens(result) & NEAR_MISS_QUALITIES:
        return True
    for evidence in result.evidence_updates:
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        evidence_ctx = extracted.get("output_context")
        if isinstance(evidence_ctx, dict) and (
            evidence_ctx.get("near_miss_candidates")
            or evidence_ctx.get("flag_candidates")
        ):
            return True
    return False


def is_no_progress_result(result: WorkerResult) -> bool:
    return bool(quality_tokens(result) & NO_PROGRESS_QUALITIES)


def is_hollow_result(result: WorkerResult) -> bool:
    """Detect successful results that produced no state signal or observation."""
    if not result.success or result.partial or result.solved:
        return False
    delta = result.state_delta
    if delta and (
        delta.flag_candidates
        or delta.artifacts
        or delta.endpoints
        or delta.routes
        or delta.hypotheses
        or delta.vulnerabilities
        or delta.exploit_attempts
        or delta.sessions
    ):
        return False
    ctx = result.output_context or {}
    if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
        return False
    if has_observation_text(ctx):
        return False
    for evidence in result.evidence_updates:
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        evidence_ctx = extracted.get("output_context")
        if isinstance(evidence_ctx, dict) and has_observation_text(evidence_ctx):
            return False
        evidence_result = evidence.result if isinstance(evidence.result, dict) else {}
        if has_observation_text(evidence_result):
            return False
    if result.result_quality:
        return False
    if result.finding_updates or result.credential_updates:
        return False
    return True
