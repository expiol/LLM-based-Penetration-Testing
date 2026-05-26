"""Shared policy helpers for artifact-derived planning seeds."""

from __future__ import annotations

from killchain_docker.orchestrator.todo_queue import TodoQueue
from killchain_docker.state.artifact_projection import ArtifactProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.tools.capabilities import dispatch_profile_for_capability

FILES_ROOT = "/home/ctfplayer/ctf_files"
MAX_ARTIFACT_FOLLOWUP_SEEDS = 12
MAX_ARTIFACT_TRIAGE_BATCH_PATHS = 8
MAX_MEDIA_SCAN_BATCH_PATHS = 12


def artifact_evidence_ids(artifact: ArtifactProjection) -> list[str]:
    return list(artifact.evidence_ids)


def artifacts_evidence_ids(artifacts: list[ArtifactProjection]) -> list[str]:
    out: list[str] = []
    for artifact in artifacts:
        for evidence_id in artifact_evidence_ids(artifact):
            if evidence_id not in out:
                out.append(evidence_id)
    return out


def has_artifact_followup_path(state: RunState, path: str) -> bool:
    target = str(path or "").strip()
    if not target:
        return False
    for todo in TodoQueue(state).recent(limit=10000):
        is_artifact_followup = (
            str(todo.context.get("family") or "") == "artifact-followup"
        )
        if str(todo.context.get("path") or "").strip() == target:
            if is_artifact_followup:
                return True
        if str(todo.context.get("artifact_path") or "").strip() == target:
            if is_artifact_followup:
                return True
        if str(todo.context.get("executed_path") or "").strip() == target:
            return True
        paths = todo.context.get("paths")
        if isinstance(paths, list) and target in {str(item).strip() for item in paths}:
            if is_artifact_followup:
                return True
        executed_paths = todo.context.get("executed_paths")
        if isinstance(executed_paths, list) and target in {
            str(item).strip() for item in executed_paths
        }:
            return True
    return False


def has_capability_todo_for_path(state: RunState, path: str, capability: str) -> bool:
    target = str(path or "").strip()
    expected = str(capability or "").strip()
    if not target or not expected:
        return False
    for todo in TodoQueue(state).recent(limit=10000):
        current_capability = ""
        intent = todo.context.get("dispatch_intent")
        if isinstance(intent, dict):
            current_capability = str(intent.get("required_capability") or "").strip()
        if current_capability != expected:
            current_capability = str(
                todo.context.get("executed_capability") or ""
            ).strip()
        if current_capability != expected:
            continue
        if str(todo.context.get("path") or "").strip() == target:
            return True
        if str(todo.context.get("artifact_path") or "").strip() == target:
            return True
        if str(todo.context.get("executed_path") or "").strip() == target:
            return True
        paths = todo.context.get("paths")
        if isinstance(paths, list) and target in {str(item).strip() for item in paths}:
            return True
        executed_paths = todo.context.get("executed_paths")
        if isinstance(executed_paths, list) and target in {
            str(item).strip() for item in executed_paths
        }:
            return True
    return False


def artifact_followup_todo_priority(
    artifact: ArtifactProjection, capability: str
) -> int:
    if capability in {"office.inspect", "png.inspect"}:
        return 91
    if capability == "media.scan":
        return 90
    score = artifact.followup_priority
    if score >= 90:
        return 89
    if score >= 80:
        return 84
    if score >= 60:
        return 78
    return 70


def artifact_needs_followup(artifact: ArtifactProjection) -> bool:
    if artifact.terminal_source:
        return False
    if artifact.is_low_signal or not artifact.path:
        return False
    if artifact.source == "disk_extract":
        return artifact.followup_priority > 0
    if artifact.generated:
        return True
    return artifact.followup_priority > 0


def artifact_followup_objective(capability: str) -> tuple[str, list[str]]:
    if capability == "office.inspect":
        return (
            "Inspect Office document container deterministically.",
            [
                "Extract human-readable document text with part provenance.",
                "Register embedded media or container payloads as durable artifacts.",
                "Surface only literal flag-like evidence from the document.",
            ],
        )
    if capability == "png.inspect":
        return (
            "Inspect PNG image structure and hidden payload surfaces deterministically.",
            [
                "Parse PNG chunks and text metadata with provenance.",
                "Run bounded LSB extraction on supported PNG pixel formats.",
                "Register extracted payloads as durable artifacts when useful.",
            ],
        )
    if capability == "media.scan":
        return (
            "Batch-scan media artifacts deterministically.",
            [
                "Detect appended payloads and media metadata with source provenance.",
                "Surface only literal flag-like evidence from media strings.",
                "Register extracted payloads as durable artifacts when useful.",
            ],
        )
    return (
        "Run deterministic first-pass triage on a newly generated artifact.",
        [
            "Classify the artifact type.",
            "Extract metadata, printable strings, signatures, and flag-like evidence.",
        ],
    )


def artifact_followup_dispatch_profile(capability: str) -> str:
    profile = dispatch_profile_for_capability(capability)
    return profile if profile != "open" else "artifact_analysis"


def artifact_should_batch_media(artifact: ArtifactProjection) -> bool:
    return artifact.followup_capability == "media.scan"


def has_todo_key(state: RunState, dedupe_key: str) -> bool:
    return TodoQueue(state).has_dedupe_key(dedupe_key)
