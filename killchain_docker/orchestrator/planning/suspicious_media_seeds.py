"""Planning seeds for suspicious media findings."""

from __future__ import annotations

from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.planning.artifact_seed_common import (
    FILES_ROOT,
    has_capability_todo_for_path,
)
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state.artifact_projection import ArtifactProjectionStore
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class SuspiciousMediaSeedPlanner:
    """Build deterministic follow-up todos for suspicious media evidence."""

    def seed_todos(self, state: RunState) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return ([], [])
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        seen_paths: set[str] = set()
        evidence_projection = EvidenceProjectionStore(state)
        artifacts = ArtifactProjectionStore(state)
        for evidence_record in evidence_projection.media_scan_records():
            evidence_id = evidence_record.evidence_id
            ctx = evidence_record.output_context
            media_records = ctx.get("media")
            for record in media_records:
                if not isinstance(record, dict) or not record.get("suspicious"):
                    continue
                path = str(record.get("path") or "").strip()
                if not path or path in seen_paths:
                    continue
                artifact = artifacts.by_path(path)
                is_png = (
                    artifact.is_png
                    if artifact is not None
                    else _media_record_is_png(record)
                )
                if not is_png:
                    continue
                if has_capability_todo_for_path(state, path, "png.inspect"):
                    continue
                key_material = (
                    str(artifact.digest or "").strip() if artifact is not None else ""
                ) or path
                artifact_id = artifact.artifact_id if artifact is not None else ""
                todos.append(
                    PlannedTodo(
                        goal="Inspect suspicious PNG media artifact deterministically.",
                        phase=TodoPhase.ANALYSIS,
                        priority=93,
                        context={
                            "family": "artifact-followup",
                            "dispatch_intent": {
                                "profile": "image_inspection",
                                "required_capability": "png.inspect",
                                "evidence_ids": [evidence_id],
                            },
                            "artifact_id": artifact_id,
                            "artifact_path": path,
                            "path": path,
                            "files_root": FILES_ROOT,
                            "evidence_ids": [evidence_id],
                            "novelty_key": f"suspicious-png-inspect:{key_material}",
                        },
                        success_criteria=[
                            "Parse PNG chunks, text metadata, and bounded LSB surfaces.",
                            "Register extracted payloads as durable artifacts with source provenance.",
                        ],
                        constraints=[
                            "Use deterministic PNG inspection before generated scripts."
                        ],
                        dedupe_key=f"bootstrap:suspicious-png-inspect:{key_material}",
                    )
                )
                seen_paths.add(path)
                notes.append(f"Seeded suspicious PNG inspection todo for {path}.")
        return (todos, notes)


def _media_record_is_png(record: dict[str, object]) -> bool:
    kind = str(record.get("kind") or "").strip().lower()
    file_type = str(record.get("file_type") or "").strip().lower()
    mime_type = (
        str(
            record.get("mime_type")
            or record.get("content_type")
            or record.get("media_type")
            or ""
        )
        .strip()
        .lower()
    )
    return (
        kind == "png"
        or mime_type == "image/png"
        or "image/png" in mime_type
        or ("png image" in file_type)
        or ("portable network graphics" in file_type)
    )
