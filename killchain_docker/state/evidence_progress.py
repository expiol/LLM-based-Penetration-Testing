"""Evidence usefulness checks shared by planner and progress policy."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.progress_qualities import NO_PROGRESS_QUALITIES

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


def evidence_ref_can_unlock_progress(state: "RunState", evidence_id: str) -> bool:
    evidence = state.evidence.get(evidence_id)
    if evidence is None:
        return False
    extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
    ctx = extracted.get("output_context")
    ctx = ctx if isinstance(ctx, dict) else {}
    if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
        return True
    if (
        ctx.get("generated_artifacts_durable")
        or ctx.get("generated_artifact_records")
        or ctx.get("extracted_files_durable")
        or ctx.get("extracted_file_records")
    ):
        return True
    quality_tokens = {
        str(ctx.get("result_quality") or "").strip().lower(),
        str(ctx.get("failure_kind") or "").strip().lower(),
    }
    quality_tokens.discard("")
    if quality_tokens and quality_tokens <= NO_PROGRESS_QUALITIES:
        return False
    return True


def evidence_ref_supports_exploit_continuation(
    state: "RunState", evidence_id: str
) -> bool:
    evidence = state.evidence.get(evidence_id)
    if evidence is None:
        return False
    searchable = " ".join(
        (
            evidence.summary,
            evidence.tool_name,
            str(evidence.capability or ""),
            str(evidence.request),
            str(evidence.result),
            str(evidence.extracted),
        )
    ).lower()
    return any(
        token in searchable
        for token in (
            "http",
            "tcp",
            "socket",
            "remote",
            "service",
            "endpoint",
            "protocol",
            "connected",
        )
    )
