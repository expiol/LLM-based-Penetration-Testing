"""Meaningful-progress classification for a worker result round."""

from __future__ import annotations

from killchain_docker.orchestrator.progress.result_signals import (
    has_near_miss_signal,
    has_observation_text,
    is_no_progress_result,
)
from killchain_docker.state.todos import WorkerResult


def had_meaningful_progress(results: list[WorkerResult]) -> bool:
    """Return true when a round emitted durable progress signals."""
    for result in results:
        delta = result.state_delta
        if result.partial:
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
                return True
            if result.finding_updates or result.credential_updates:
                return True
            ctx = result.output_context or {}
            if has_near_miss_signal(result):
                return True
            if is_no_progress_result(result):
                return False
            if has_observation_text(ctx):
                return True
            for evidence in result.evidence_updates:
                extracted = (
                    evidence.extracted if isinstance(evidence.extracted, dict) else {}
                )
                evidence_ctx = extracted.get("output_context")
                if isinstance(evidence_ctx, dict) and has_observation_text(
                    evidence_ctx
                ):
                    return True
                evidence_result = (
                    evidence.result if isinstance(evidence.result, dict) else {}
                )
                if has_observation_text(evidence_result):
                    return True
        if not result.success:
            continue
        if delta and (
            delta.flag_candidates
            or delta.vulnerabilities
            or delta.sessions
            or delta.exploit_attempts
        ):
            return True
        if result.finding_updates or result.credential_updates:
            return True
        if has_near_miss_signal(result):
            return True
    return False
