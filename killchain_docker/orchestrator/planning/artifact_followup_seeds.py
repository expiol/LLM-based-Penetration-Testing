"""Planning seeds for generated artifact follow-up analysis."""

from __future__ import annotations

from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.orchestrator.planning.artifact_seed_common import (
    FILES_ROOT,
    MAX_ARTIFACT_FOLLOWUP_SEEDS,
    MAX_ARTIFACT_TRIAGE_BATCH_PATHS,
    MAX_MEDIA_SCAN_BATCH_PATHS,
    artifact_followup_dispatch_profile,
    artifact_followup_objective,
    artifact_followup_todo_priority,
    artifact_needs_followup,
    artifact_should_batch_media,
    artifacts_evidence_ids,
    has_artifact_followup_path,
    has_todo_key,
)
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state.artifact_projection import (
    ArtifactProjection,
    ArtifactProjectionStore,
)
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class ArtifactFollowupSeedPlanner:
    """Build deterministic follow-up todos for generated artifacts."""

    def seed_todos(self, state: RunState) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return ([], [])
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        triage_batch: list[ArtifactProjection] = []
        media_batch: list[ArtifactProjection] = []
        for artifact in ArtifactProjectionStore(state).sorted_followups():
            if len(todos) >= MAX_ARTIFACT_FOLLOWUP_SEEDS:
                notes.append(
                    "Deferred additional artifact follow-up todos to keep fan-out bounded."
                )
                break
            if not artifact_needs_followup(artifact):
                continue
            key_material = artifact.key_material
            dedupe_key = f"bootstrap:artifact-followup:{key_material}"
            if has_todo_key(state, dedupe_key) or has_artifact_followup_path(
                state, artifact.path
            ):
                continue
            if artifact_should_batch_media(artifact):
                media_batch.append(artifact)
                if len(media_batch) >= MAX_MEDIA_SCAN_BATCH_PATHS:
                    batch = self._media_scan_batch_todo(media_batch)
                    if batch is not None:
                        todos.append(batch)
                        notes.append(
                            f"Seeded batched media scan todo for {len(media_batch)} media artifact(s)."
                        )
                    media_batch = []
                continue
            capability = artifact.followup_capability
            if capability == "artifact.triage":
                triage_batch.append(artifact)
                if len(triage_batch) >= MAX_ARTIFACT_TRIAGE_BATCH_PATHS:
                    batch = self._artifact_triage_batch_todo(triage_batch)
                    if batch is not None:
                        todos.append(batch)
                        notes.append(
                            f"Seeded batched artifact follow-up todo for {len(triage_batch)} generated artifact(s)."
                        )
                    triage_batch = []
                continue
            goal, success_criteria = artifact_followup_objective(capability)
            evidence_ids = list(artifact.evidence_ids)
            dispatch_intent: dict[str, object] = {
                "profile": artifact_followup_dispatch_profile(capability),
                "required_capability": capability,
            }
            if evidence_ids:
                dispatch_intent["evidence_ids"] = evidence_ids
            todos.append(
                PlannedTodo(
                    goal=goal,
                    phase=TodoPhase.ANALYSIS,
                    priority=artifact_followup_todo_priority(artifact, capability),
                    context={
                        "family": "artifact-followup",
                        "dispatch_intent": dispatch_intent,
                        "artifact_id": artifact.artifact_id,
                        "artifact_path": artifact.path,
                        "path": artifact.path,
                        "files_root": FILES_ROOT,
                        "novelty_key": f"artifact-followup:{key_material}",
                        **({"evidence_ids": evidence_ids} if evidence_ids else {}),
                    },
                    success_criteria=success_criteria,
                    constraints=[
                        "Use bounded read-only inspection before deeper generated scripts."
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded artifact follow-up todo for {artifact.artifact_id}.")
        if media_batch and len(todos) < MAX_ARTIFACT_FOLLOWUP_SEEDS:
            batch = self._media_scan_batch_todo(media_batch)
            if batch is not None:
                todos.append(batch)
                notes.append(
                    f"Seeded batched media scan todo for {len(media_batch)} media artifact(s)."
                )
        if triage_batch and len(todos) < MAX_ARTIFACT_FOLLOWUP_SEEDS:
            batch = self._artifact_triage_batch_todo(triage_batch)
            if batch is not None:
                todos.append(batch)
                notes.append(
                    f"Seeded batched artifact follow-up todo for {len(triage_batch)} generated artifact(s)."
                )
        return (todos, notes)

    @staticmethod
    def _media_scan_batch_todo(
        artifacts: list[ArtifactProjection],
    ) -> PlannedTodo | None:
        paths = [item.path for item in artifacts]
        paths = [path for path in paths if path]
        if not paths:
            return None
        artifact_ids = [item.artifact_id for item in artifacts]
        evidence_ids = artifacts_evidence_ids(artifacts)
        key_parts = [item.key_material for item in artifacts]
        key_parts = [part for part in key_parts if part]
        batch_key = "|".join(key_parts)
        context: dict[str, object] = {
            "family": "artifact-followup",
            "dispatch_intent": {
                "profile": "media_inspection",
                "required_capability": "media.scan",
                **({"evidence_ids": evidence_ids} if evidence_ids else {}),
            },
            "artifact_ids": artifact_ids,
            "paths": paths,
            "files_root": FILES_ROOT,
            "novelty_key": f"media-scan:{batch_key}",
            **({"evidence_ids": evidence_ids} if evidence_ids else {}),
        }
        dedupe_key = f"bootstrap:media-scan-batch:{batch_key}"
        if len(paths) == 1:
            context["artifact_id"] = artifact_ids[0] if artifact_ids else ""
            context["artifact_path"] = paths[0]
            context["path"] = paths[0]
            context["novelty_key"] = (
                f"media-scan:{(key_parts[0] if key_parts else paths[0])}"
            )
            dedupe_key = (
                f"bootstrap:media-scan:{(key_parts[0] if key_parts else paths[0])}"
            )
        return PlannedTodo(
            goal="Batch-scan media artifacts deterministically.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context=context,
            success_criteria=[
                "Inspect media files for appended payloads, keyword strings, and literal flag evidence.",
                "Register extracted payloads as durable artifacts with source provenance.",
                "Summarize only bounded high-signal findings before deeper per-file analysis.",
            ],
            constraints=[
                "Use bounded read-only media inspection before generated scripts or per-image fan-out."
            ],
            dedupe_key=dedupe_key,
        )

    @staticmethod
    def _artifact_triage_batch_todo(
        artifacts: list[ArtifactProjection],
    ) -> PlannedTodo | None:
        paths: list[str] = []
        artifact_ids: list[str] = []
        key_parts: list[str] = []
        evidence_ids = artifacts_evidence_ids(artifacts)
        priority = 70
        for artifact in artifacts[:MAX_ARTIFACT_TRIAGE_BATCH_PATHS]:
            path = artifact.path
            if not path or path in paths:
                continue
            paths.append(path)
            artifact_ids.append(artifact.artifact_id)
            key_parts.append(artifact.key_material)
            priority = max(
                priority,
                artifact_followup_todo_priority(artifact, "artifact.triage"),
            )
        if not paths:
            return None
        batch_key = "|".join(key_parts)
        goal, success_criteria = artifact_followup_objective("artifact.triage")
        context: dict[str, object] = {
            "family": "artifact-followup",
            "dispatch_intent": {
                "profile": "artifact_analysis",
                "required_capability": "artifact.triage",
                **({"evidence_ids": evidence_ids} if evidence_ids else {}),
            },
            "artifact_ids": [item for item in artifact_ids if item],
            "paths": paths,
            "files_root": FILES_ROOT,
            "novelty_key": f"artifact-followup-batch:{batch_key}",
            **({"evidence_ids": evidence_ids} if evidence_ids else {}),
        }
        dedupe_key = f"bootstrap:artifact-followup-batch:{batch_key}"
        if len(paths) == 1:
            context["artifact_id"] = artifact_ids[0] if artifact_ids else ""
            context["artifact_path"] = paths[0]
            context["path"] = paths[0]
            context["novelty_key"] = f"artifact-followup:{key_parts[0]}"
            dedupe_key = f"bootstrap:artifact-followup:{key_parts[0]}"
        return PlannedTodo(
            goal=goal,
            phase=TodoPhase.ANALYSIS,
            priority=priority,
            context=context,
            success_criteria=success_criteria,
            constraints=[
                "Use bounded read-only inspection before deeper generated scripts."
            ],
            dedupe_key=dedupe_key,
        )
