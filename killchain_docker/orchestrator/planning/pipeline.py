"""Planning pipeline for seed, normalization, dedupe, and progress gates."""

from __future__ import annotations

from urllib.parse import urlparse

from killchain_docker.orchestrator.planning.schemas import (
    PlannedTodo,
    PlannerAgent,
    PlannerDecision,
)
from killchain_docker.orchestrator.policy import (
    CandidatePolicy,
    ContextRefPolicy,
    ProgressPolicy,
    TodoPolicy,
)
from killchain_docker.scope_guard import (
    todo_ephemeral_artifact_dependency_reason,
    todo_loopback_block_reason,
    todo_registered_scratch_dependency_reason,
)
from killchain_docker.state import (
    RunState,
    TodoPhase,
    TodoStatus,
    artifact_followup_capability,
    artifact_followup_priority,
    artifact_followup_profile,
    facts_from_artifact,
    todo_phase_rank,
)


_MAX_ARTIFACT_FOLLOWUP_SEEDS = 12
_MAX_ARTIFACT_TRIAGE_BATCH_PATHS = 8
_MAX_MEDIA_SCAN_BATCH_PATHS = 12


class PlanningPipeline(PlannerAgent):
    """Deterministic planner post-processor and seed planner.

    The LLM planner proposes intent.  This pipeline decides which proposed
    todos are allowed to enter the queue.
    """

    def plan(self, state: RunState) -> PlannerDecision:
        todos, notes = self.seed_todos(state)
        return PlannerDecision(
            summary=f"Planning pipeline proposed {len(todos)} seed todo(s).",
            todos=todos,
            notes=notes,
        )

    def merge(
        self,
        state: RunState,
        *,
        llm_decision: PlannerDecision | None,
    ) -> PlannerDecision:
        llm_todos = list((llm_decision.todos if llm_decision else []) or [])
        seed_todos, seed_notes = self.seed_todos(
            state,
            include_execution_closure_seed=self._include_execution_closure_seed(state, llm_todos),
        )
        notes = list((llm_decision.notes if llm_decision else []) or [])
        notes.extend(seed_notes)

        normalized: list[PlannedTodo] = []
        for todo in [*seed_todos, *llm_todos]:
            TodoPolicy.normalize(todo, state)
            normalized.append(todo)

        deduped, dedupe_notes = self._dedupe(normalized, state)
        gated, gate_notes = self._phase_gate(deduped, state)
        scoped, scope_notes = self._scope_gate(gated, state)
        allowed, progress_notes = self._progress_gate(scoped, state)

        return PlannerDecision(
            summary=(llm_decision.summary if llm_decision else "")
            or f"Planning pipeline proposed {len(allowed)} todo(s).",
            todos=allowed,
            notes=[*notes, *dedupe_notes, *gate_notes, *scope_notes, *progress_notes],
            stop_run=bool(llm_decision.stop_run) if llm_decision else False,
        )

    def seed_todos(
        self,
        state: RunState,
        *,
        include_execution_closure_seed: bool = True,
    ) -> tuple[list[PlannedTodo], list[str]]:
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        challenge = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge.get("files", []) or [])

        if challenge_files and not self._has_todo_key(state, "bootstrap:artifact-inventory"):
            todos.append(
                PlannedTodo(
                    goal="Inventory and classify bundled challenge files.",
                    phase=TodoPhase.RECON,
                    priority=95,
                    context={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "challenge_files": challenge_files,
                        "family": "artifact-inventory",
                        "capability_hint": "artifact.triage",
                        "dispatch_intent": {
                            "profile": "artifact_analysis",
                            "required_capability": "artifact.triage",
                        },
                    },
                    success_criteria=[
                        "Classify files by kind.",
                        "Surface source, binary, archive, database, pcap, repo, and flag-like evidence.",
                    ],
                    constraints=["Use only files under /home/ctfplayer/ctf_files."],
                    dedupe_key="bootstrap:artifact-inventory",
                )
            )

        if include_execution_closure_seed:
            closure_seed = self._execution_closure_seed(state, challenge_files)
            if closure_seed is not None:
                todos.append(closure_seed)

        for candidate in CandidatePolicy.validation_ready_candidates(state)[:1]:
            dedupe_key = f"bootstrap:flag-validation:{candidate.value}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal="Validate recovered flag candidate.",
                    phase=TodoPhase.FLAG_VALIDATION,
                    priority=100,
                    context={
                        "candidate_flag": candidate.value,
                        "flag_candidate_id": candidate.candidate_id,
                        "family": "flag-validation",
                        "dispatch_intent": {
                            "profile": "flag_validation",
                        },
                    },
                    success_criteria=["Confirm whether the candidate is the challenge flag."],
                    constraints=["Validate only grounded candidates already present in state."],
                    dedupe_key=dedupe_key,
                )
            )

        artifact_todos, artifact_notes = self._artifact_followup_seeds(state)
        todos.extend(artifact_todos)
        notes.extend(artifact_notes)

        suspicious_media_todos, suspicious_media_notes = self._suspicious_media_followup_seeds(state)
        todos.extend(suspicious_media_todos)
        notes.extend(suspicious_media_notes)

        disk_todos, disk_notes = self._disk_extract_seeds(state)
        todos.extend(disk_todos)
        notes.extend(disk_notes)

        recovery_todos, recovery_notes = self._candidate_recovery_seeds(
            state,
            challenge_files,
        )
        todos.extend(recovery_todos)
        notes.extend(recovery_notes)

        for index, scope in enumerate(state.authorized_scope, start=1):
            dedupe_key = f"bootstrap:scope:{scope}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal=f"Map authorized scope entry {index}.",
                    phase=TodoPhase.RECON,
                    priority=100,
                    context={
                        "scope": scope,
                        "asset_id": "seed-asset" if len(state.authorized_scope) == 1 else f"seed-asset-{index}",
                        "family": "recon",
                    },
                    success_criteria=[
                        "Create or update a tracked asset.",
                        "Collect first-pass service or HTTP metadata when possible.",
                    ],
                    constraints=["Stay inside the authorized scope entry."],
                    dedupe_key=dedupe_key,
                )
            )

        # Seed near-miss refinement todos only for decode/decrypt contexts.
        # Protocol solvers can emit readable partial output that is not a
        # byte-level plaintext recovery signal.
        for evidence_id, evidence in list(state.evidence.items()):
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context") or {}
            near_misses = list(ctx.get("near_miss_candidates") or [])
            if not near_misses:
                continue
            if not self._near_miss_refinement_allowed(state, evidence, ctx, near_misses):
                continue
            dedupe_key = f"bootstrap:near-miss-refinement:{evidence_id}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal="Resolve near-miss output from grounded evidence.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={
                        "family": "crypto-decrypt",
                        "capability_hint": "script.exec",
                        "dispatch_intent": {
                            "profile": "near_miss_repair",
                            "required_capability": "script.exec",
                        },
                        "evidence_ids": [evidence_id],
                        "near_miss_candidates": near_misses[:3],
                        "novelty_key": f"near-miss:{evidence_id}",
                        "files_root": str(ctx.get("files_root") or "/home/ctfplayer/ctf_files"),
                        "challenge_files": challenge_files,
                    },
                    success_criteria=["Produce a valid flag candidate from the near-miss output."],
                    constraints=[
                        "Use only current-state evidence and authorized challenge artifacts.",
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded near-miss refinement todo for evidence {evidence_id}.")

        if not todos and not state.todos:
            notes.append("No authorized scope or challenge files are available for bootstrap.")
        return todos, notes

    @classmethod
    def _suspicious_media_followup_seeds(
        cls,
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return [], []
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        seen_paths: set[str] = set()
        for evidence_id, evidence in state.evidence.items():
            if evidence.tool_name != "media_scan":
                continue
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context")
            if not isinstance(ctx, dict):
                continue
            media_records = ctx.get("media")
            if not isinstance(media_records, list):
                continue
            for record in media_records:
                if not isinstance(record, dict) or not record.get("suspicious"):
                    continue
                path = str(record.get("path") or "").strip()
                if not path or path in seen_paths:
                    continue
                artifact = cls._artifact_for_path(state, path)
                if artifact is not None:
                    is_png = facts_from_artifact(artifact).is_png
                else:
                    is_png = cls._media_record_is_png(record)
                if not is_png:
                    continue
                if cls._has_capability_todo_for_path(state, path, "png.inspect"):
                    continue
                key_material = (
                    str(getattr(artifact, "digest", "") or "").strip()
                    if artifact is not None
                    else ""
                ) or path
                artifact_id = str(getattr(artifact, "artifact_id", "") or "").strip() if artifact is not None else ""
                todos.append(
                    PlannedTodo(
                        goal="Inspect suspicious PNG media artifact deterministically.",
                        phase=TodoPhase.ANALYSIS,
                        priority=93,
                        context={
                            "family": "artifact-followup",
                            "capability_hint": "png.inspect",
                            "dispatch_intent": {
                                "profile": "image_inspection",
                                "required_capability": "png.inspect",
                                "evidence_ids": [evidence_id],
                            },
                            "artifact_id": artifact_id,
                            "artifact_path": path,
                            "path": path,
                            "files_root": "/home/ctfplayer/ctf_files",
                            "evidence_ids": [evidence_id],
                            "novelty_key": f"suspicious-png-inspect:{key_material}",
                        },
                        success_criteria=[
                            "Parse PNG chunks, text metadata, and bounded LSB surfaces.",
                            "Register extracted payloads as durable artifacts with source provenance.",
                        ],
                        constraints=[
                            "Use deterministic PNG inspection before generated scripts.",
                        ],
                        dedupe_key=f"bootstrap:suspicious-png-inspect:{key_material}",
                    )
                )
                seen_paths.add(path)
                notes.append(f"Seeded suspicious PNG inspection todo for {path}.")
        return todos, notes

    @staticmethod
    def _media_record_is_png(record: dict[str, object]) -> bool:
        kind = str(record.get("kind") or "").strip().lower()
        file_type = str(record.get("file_type") or "").strip().lower()
        mime_type = str(
            record.get("mime_type")
            or record.get("content_type")
            or record.get("media_type")
            or ""
        ).strip().lower()
        return (
            kind == "png"
            or mime_type == "image/png"
            or "image/png" in mime_type
            or "png image" in file_type
            or "portable network graphics" in file_type
        )

    @classmethod
    def _artifact_followup_seeds(
        cls,
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return [], []
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        artifacts = sorted(
            state.artifacts.values(),
            key=cls._artifact_followup_priority,
            reverse=True,
        )
        triage_batch: list[object] = []
        media_batch: list[object] = []
        for artifact in artifacts:
            if len(todos) >= _MAX_ARTIFACT_FOLLOWUP_SEEDS:
                notes.append(
                    "Deferred additional artifact follow-up todos to keep fan-out bounded."
                )
                break
            if not cls._artifact_needs_followup(artifact, state):
                continue
            key_material = artifact.digest or artifact.path
            dedupe_key = f"bootstrap:artifact-followup:{key_material}"
            if cls._has_todo_key(state, dedupe_key) or cls._has_artifact_followup_path(state, artifact.path):
                continue
            if cls._artifact_should_batch_media(artifact):
                media_batch.append(artifact)
                if len(media_batch) >= _MAX_MEDIA_SCAN_BATCH_PATHS:
                    batch = cls._media_scan_batch_todo(media_batch)
                    if batch is not None:
                        todos.append(batch)
                        notes.append(
                            "Seeded batched media scan todo for "
                            f"{len(media_batch)} embedded media artifact(s)."
                        )
                    media_batch = []
                continue
            capability = cls._artifact_followup_capability(artifact)
            if capability == "artifact.triage":
                triage_batch.append(artifact)
                if len(triage_batch) >= _MAX_ARTIFACT_TRIAGE_BATCH_PATHS:
                    batch = cls._artifact_triage_batch_todo(triage_batch)
                    if batch is not None:
                        todos.append(batch)
                        notes.append(
                            "Seeded batched artifact follow-up todo for "
                            f"{len(triage_batch)} generated artifact(s)."
                        )
                    triage_batch = []
                continue
            goal, success_criteria = cls._artifact_followup_objective(capability)
            evidence_ids = cls._artifact_evidence_ids(artifact)
            dispatch_intent: dict[str, object] = {
                "profile": cls._artifact_followup_dispatch_profile(capability),
                "required_capability": capability,
            }
            if evidence_ids:
                dispatch_intent["evidence_ids"] = evidence_ids
            todos.append(
                PlannedTodo(
                    goal=goal,
                    phase=TodoPhase.ANALYSIS,
                    priority=cls._artifact_followup_todo_priority(artifact, capability),
                    context={
                        "family": "artifact-followup",
                        "capability_hint": capability,
                        "dispatch_intent": dispatch_intent,
                        "artifact_id": artifact.artifact_id,
                        "artifact_path": artifact.path,
                        "path": artifact.path,
                        "files_root": "/home/ctfplayer/ctf_files",
                        "novelty_key": f"artifact-followup:{key_material}",
                        **({"evidence_ids": evidence_ids} if evidence_ids else {}),
                    },
                    success_criteria=success_criteria,
                    constraints=[
                        "Use bounded read-only inspection before deeper generated scripts.",
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded artifact follow-up todo for {artifact.artifact_id}.")
        if media_batch and len(todos) < _MAX_ARTIFACT_FOLLOWUP_SEEDS:
            batch = cls._media_scan_batch_todo(media_batch)
            if batch is not None:
                todos.append(batch)
                notes.append(
                    "Seeded batched media scan todo for "
                    f"{len(media_batch)} embedded media artifact(s)."
                )
        if triage_batch and len(todos) < _MAX_ARTIFACT_FOLLOWUP_SEEDS:
            batch = cls._artifact_triage_batch_todo(triage_batch)
            if batch is not None:
                todos.append(batch)
                notes.append(
                    "Seeded batched artifact follow-up todo for "
                    f"{len(triage_batch)} generated artifact(s)."
                )
        return todos, notes

    @staticmethod
    def _media_scan_batch_todo(artifacts: list[object]) -> PlannedTodo | None:
        paths = [str(getattr(item, "path", "") or "") for item in artifacts]
        paths = [path for path in paths if path]
        if not paths:
            return None
        artifact_ids = [str(getattr(item, "artifact_id", "") or "") for item in artifacts]
        evidence_ids = PlanningPipeline._artifacts_evidence_ids(artifacts)
        key_parts = [
            str(getattr(item, "digest", None) or getattr(item, "path", "") or "")
            for item in artifacts
        ]
        key_parts = [part for part in key_parts if part]
        batch_key = "|".join(key_parts)
        context: dict[str, object] = {
            "family": "artifact-followup",
            "capability_hint": "media.scan",
            "dispatch_intent": {
                "profile": "media_inspection",
                "required_capability": "media.scan",
                **({"evidence_ids": evidence_ids} if evidence_ids else {}),
            },
            "artifact_ids": artifact_ids,
            "paths": paths,
            "files_root": "/home/ctfplayer/ctf_files",
            "novelty_key": f"media-scan:{batch_key}",
            **({"evidence_ids": evidence_ids} if evidence_ids else {}),
        }
        dedupe_key = f"bootstrap:media-scan-batch:{batch_key}"
        if len(paths) == 1:
            context["artifact_id"] = artifact_ids[0] if artifact_ids else ""
            context["artifact_path"] = paths[0]
            context["path"] = paths[0]
            context["novelty_key"] = f"media-scan:{key_parts[0] if key_parts else paths[0]}"
            dedupe_key = f"bootstrap:media-scan:{key_parts[0] if key_parts else paths[0]}"
        return PlannedTodo(
            goal="Batch-scan embedded media artifacts deterministically.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context=context,
            success_criteria=[
                "Inspect media files for appended payloads, keyword strings, and literal flag evidence.",
                "Register extracted payloads as durable artifacts with source provenance.",
                "Summarize only bounded high-signal findings before deeper per-file analysis.",
            ],
            constraints=[
                "Use bounded read-only media inspection before generated scripts or per-image fan-out.",
            ],
            dedupe_key=dedupe_key,
        )

    @staticmethod
    def _artifact_triage_batch_todo(artifacts: list[object]) -> PlannedTodo | None:
        paths: list[str] = []
        artifact_ids: list[str] = []
        key_parts: list[str] = []
        evidence_ids = PlanningPipeline._artifacts_evidence_ids(artifacts)
        priority = 70
        for artifact in artifacts[:_MAX_ARTIFACT_TRIAGE_BATCH_PATHS]:
            path = str(getattr(artifact, "path", "") or "").strip()
            if not path or path in paths:
                continue
            paths.append(path)
            artifact_ids.append(str(getattr(artifact, "artifact_id", "") or ""))
            key_parts.append(str(getattr(artifact, "digest", None) or path))
            priority = max(
                priority,
                PlanningPipeline._artifact_followup_todo_priority(
                    artifact,
                    "artifact.triage",
                ),
            )
        if not paths:
            return None
        batch_key = "|".join(key_parts)
        goal, success_criteria = PlanningPipeline._artifact_followup_objective(
            "artifact.triage"
        )
        context: dict[str, object] = {
            "family": "artifact-followup",
            "capability_hint": "artifact.triage",
            "dispatch_intent": {
                "profile": "artifact_analysis",
                "required_capability": "artifact.triage",
                **({"evidence_ids": evidence_ids} if evidence_ids else {}),
            },
            "artifact_ids": [item for item in artifact_ids if item],
            "paths": paths,
            "files_root": "/home/ctfplayer/ctf_files",
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
                "Use bounded read-only inspection before deeper generated scripts.",
            ],
            dedupe_key=dedupe_key,
        )

    @staticmethod
    def _artifact_evidence_ids(artifact: object) -> list[str]:
        metadata = getattr(artifact, "metadata", {}) or {}
        raw = metadata.get("evidence_ids") or metadata.get("evidence_id")
        values = raw if isinstance(raw, list) else [raw]
        out: list[str] = []
        for value in values:
            text = str(value or "").strip()
            if text and text not in out:
                out.append(text)
        return out

    @staticmethod
    def _artifacts_evidence_ids(artifacts: list[object]) -> list[str]:
        out: list[str] = []
        for artifact in artifacts:
            for evidence_id in PlanningPipeline._artifact_evidence_ids(artifact):
                if evidence_id not in out:
                    out.append(evidence_id)
        return out

    @staticmethod
    def _has_artifact_followup_path(state: RunState, path: str) -> bool:
        target = str(path or "").strip()
        if not target:
            return False
        for todo in state.todos:
            is_artifact_followup = str(todo.context.get("family") or "") == "artifact-followup"
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
            if isinstance(executed_paths, list) and target in {str(item).strip() for item in executed_paths}:
                return True
        return False

    @staticmethod
    def _has_capability_todo_for_path(
        state: RunState,
        path: str,
        capability: str,
    ) -> bool:
        target = str(path or "").strip()
        expected = str(capability or "").strip()
        if not target or not expected:
            return False
        for todo in state.todos:
            current_capability = str(todo.context.get("capability_hint") or "").strip()
            if current_capability != expected:
                intent = todo.context.get("dispatch_intent")
                if isinstance(intent, dict):
                    current_capability = str(intent.get("required_capability") or "").strip()
            if current_capability != expected:
                current_capability = str(todo.context.get("executed_capability") or "").strip()
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
            if isinstance(executed_paths, list) and target in {str(item).strip() for item in executed_paths}:
                return True
        return False

    @staticmethod
    def _artifact_for_path(state: RunState, path: str):
        target = str(path or "").strip()
        if not target:
            return None
        for artifact in state.artifacts.values():
            if str(getattr(artifact, "path", "") or "").strip() == target:
                return artifact
        return None

    @staticmethod
    def _artifact_followup_todo_priority(artifact, capability: str) -> int:
        if capability in {"office.inspect", "png.inspect"}:
            return 91
        if capability == "media.scan":
            return 90
        score = PlanningPipeline._artifact_followup_priority(artifact)
        if score >= 90:
            return 89
        if score >= 80:
            return 84
        if score >= 60:
            return 78
        return 70

    @staticmethod
    def _artifact_needs_followup(artifact, state: RunState | None = None) -> bool:
        facts = facts_from_artifact(artifact)
        if facts.terminal_source:
            return False
        if facts.is_low_signal or not facts.path:
            return False
        if facts.source == "disk_extract":
            return artifact_followup_priority(artifact) > 0
        if facts.generated:
            return True
        return artifact_followup_priority(artifact) > 0

    @staticmethod
    def _artifact_followup_priority(artifact) -> int:
        return artifact_followup_priority(artifact)

    @staticmethod
    def _artifact_followup_capability(artifact) -> str:
        return artifact_followup_capability(artifact)

    @staticmethod
    def _artifact_followup_objective(capability: str) -> tuple[str, list[str]]:
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
                "Batch-scan embedded media artifacts deterministically.",
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

    @staticmethod
    def _artifact_followup_dispatch_profile(capability: str) -> str:
        return artifact_followup_profile(capability)

    @staticmethod
    def _artifact_should_batch_media(artifact) -> bool:
        facts = facts_from_artifact(artifact)
        return facts.is_embedded_media and facts.is_media

    @classmethod
    def _disk_extract_seeds(
        cls,
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return [], []
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        for artifact in state.artifacts.values():
            if not cls._artifact_is_disk_image(artifact):
                continue
            key_material = getattr(artifact, "digest", None) or getattr(artifact, "path", "")
            dedupe_key = f"bootstrap:disk-extract:{key_material}"
            if cls._has_todo_key(state, dedupe_key):
                continue
            path = str(getattr(artifact, "path", "") or "")
            todos.append(
                PlannedTodo(
                    goal="Extract files from the detected disk image.",
                    phase=TodoPhase.ANALYSIS,
                    priority=94,
                    context={
                        "family": "forensics-extract",
                        "capability_hint": "disk.extract",
                        "dispatch_intent": {
                            "profile": "container_extraction",
                            "required_capability": "disk.extract",
                        },
                        "artifact_id": getattr(artifact, "artifact_id", ""),
                        "artifact_path": path,
                        "path": path,
                        "files_root": "/home/ctfplayer/ctf_files",
                        "novelty_key": f"disk-extract:{key_material}",
                    },
                    success_criteria=[
                        "Create durable artifacts for recovered filesystem or container files.",
                    ],
                    constraints=["Keep extraction bounded and preserve provenance."],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(f"Seeded disk extraction todo for {artifact.artifact_id}.")
        return todos, notes

    @staticmethod
    def _artifact_is_disk_image(artifact) -> bool:
        return facts_from_artifact(artifact).is_disk_image

    @classmethod
    def _candidate_recovery_seeds(
        cls,
        state: RunState,
        challenge_files: list[object],
    ) -> tuple[list[PlannedTodo], list[str]]:
        if CandidatePolicy.validation_ready_candidates(state):
            return [], []

        challenge = state.metadata.get("challenge", {}) or {}
        expected_prefix = CandidatePolicy._expected_prefix(challenge.get("flag_format"))
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        for rejected in reversed(state.rejected_flag_candidates):
            if not cls._rejection_is_actionable(rejected.reason):
                continue
            dedupe_key = f"bootstrap:candidate-recovery:{rejected.rejection_id}"
            if cls._has_todo_key(state, dedupe_key):
                continue

            context: dict[str, object] = {
                "family": "candidate-recovery",
                "dispatch_intent": {
                    "profile": "candidate_recovery",
                },
                "recovery_trigger": "validator_rejection",
                "rejected_candidate": {
                    "value": rejected.value,
                    "reason": rejected.reason,
                    "source": rejected.source,
                },
                "novelty_key": f"validator-rejection:{rejected.rejection_id}",
            }
            refs = [ref for ref in rejected.evidence_refs if ref in state.evidence]
            if refs:
                context["evidence_ids"] = refs[:3]
            if expected_prefix:
                context["flag_format_prefix"] = f"{expected_prefix}{{"
            if challenge_files:
                context["files_root"] = "/home/ctfplayer/ctf_files"
                context["challenge_files"] = list(challenge_files)

            todos.append(
                PlannedTodo(
                    goal=(
                        "Re-derive a corrected flag candidate from the original "
                        "evidence after validator rejection."
                    ),
                    phase=TodoPhase.ANALYSIS,
                    priority=96,
                    context=context,
                    success_criteria=[
                        "Explain which evidence supports or invalidates the rejected value.",
                        "Return one corrected candidate with provenance, or a blocker naming the missing fact.",
                    ],
                    constraints=[
                        "Do not resubmit the rejected value unchanged.",
                        "Use only current-state evidence and authorized challenge artifacts.",
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(
                "Seeded candidate recovery todo from validator feedback "
                f"{rejected.rejection_id}."
            )
            break
        return todos, notes

    @staticmethod
    def _rejection_is_actionable(reason: str) -> bool:
        return reason not in {
            "empty_candidate",
            "escaped_byte_candidate",
            "invalid_candidate_shape",
            "invalid_prefix_candidate",
        }

    @classmethod
    def _execution_closure_seed(
        cls,
        state: RunState,
        challenge_files: list[object],
    ) -> PlannedTodo | None:
        if CandidatePolicy.validation_ready_candidates(state):
            return None
        if not challenge_files:
            return None
        if not cls._artifact_inventory_completed(state):
            return None
        dedupe_key = "bootstrap:evidence-execution-closure"
        if cls._has_todo_key(state, dedupe_key):
            return None
        return PlannedTodo(
            goal=(
                "Build and run a bounded solver harness from current evidence "
                "and local challenge artifacts."
            ),
            phase=TodoPhase.ANALYSIS,
            priority=92,
            context={
                "family": cls._execution_closure_family(state),
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": list(challenge_files),
                "capability_hint": "script.exec",
                "execution_closure": True,
                "dispatch_intent": {
                    "profile": "execution_closure",
                    "required_capability": "script.exec",
                },
            },
            success_criteria=[
                "Use only local artifacts or authorized runtime evidence.",
                "Return any recovered candidate through normal tool output.",
            ],
            constraints=[
                "Do not copy or guess a flag from supplemental context.",
                "Use installed tools or Python standard library; do not install packages.",
                "Keep loops and searches bounded.",
            ],
            dedupe_key=dedupe_key,
        )

    @classmethod
    def _include_execution_closure_seed(
        cls,
        state: RunState,
        llm_todos: list[PlannedTodo],
    ) -> bool:
        if llm_todos:
            return False
        return cls._artifact_inventory_completed(state)

    @staticmethod
    def _artifact_inventory_completed(state: RunState) -> bool:
        return any(
            todo.dedupe_key == "bootstrap:artifact-inventory"
            and todo.status == TodoStatus.COMPLETED
            for todo in state.todos
        )

    @staticmethod
    def _execution_closure_family(state: RunState) -> str:
        category = str(
            (state.metadata.get("challenge", {}) or {}).get("category") or ""
        ).strip().lower()
        if category in {"forensics", "forensic", "stego", "steganography"}:
            return "forensics-extract"
        if category in {"rev", "reversing", "pwn"}:
            return "algorithm-verification"
        if category in {"crypto", "cryptography", "misc"}:
            return "algorithm-verification"
        return "technical-context-execution"

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return any(todo.dedupe_key == dedupe_key for todo in state.todos)

    _NEAR_MISS_CATEGORIES = frozenset({
        "crypto",
        "cryptography",
        "forensics",
        "forensic",
        "stego",
        "steganography",
    })
    _NEAR_MISS_STRONG_TERMS = frozenset({
        "base32",
        "base64",
        "cipher",
        "ciphertext",
        "codec",
        "decode",
        "decrypt",
        "encoding",
        "flag text",
        "hidden text",
        "keystream",
        "latin-1",
        "lfsr",
        "mojibake",
        "ocr",
        "plaintext",
        "plain text",
        "recover text",
        "stego",
        "xor",
    })
    _NEAR_MISS_WEAK_TERMS = frozenset({
        "ascii",
        "ascii-art",
        "garbled",
        "hex",
        "unicode",
    })
    _NEAR_MISS_PROTOCOL_TERMS = frozenset({
        "broken pipe",
        "connect",
        "connection",
        "http",
        "menu",
        "netcat",
        "prompt",
        "protocol",
        "raw tcp",
        "remote",
        "round ",
        "socket",
        "tcp",
        "telnet",
    })

    @staticmethod
    def _near_miss_refinement_allowed(
        state: RunState,
        evidence,
        ctx: dict,
        near_misses: list[object],
    ) -> bool:
        texts = [
            evidence.summary,
            evidence.tool_name,
            evidence.capability or "",
            str(ctx.get("failure_kind") or ""),
            str(ctx.get("failure_detail") or ""),
            str(ctx.get("partial_reason") or ""),
            str(ctx.get("result_quality") or ""),
            str(ctx.get("stdout") or ""),
            str(ctx.get("stderr") or ""),
            PlanningPipeline._near_miss_candidate_body(near_misses),
        ]
        todo = state.get_todo(evidence.task_id)
        if todo is not None:
            texts.extend([
                todo.goal,
                todo.result_summary,
                todo.error or "",
                " ".join(todo.success_criteria),
                " ".join(todo.constraints),
                " ".join(str(value) for value in todo.context.values()),
            ])
        haystack = "\n".join(texts).lower()
        has_strong_decode_signal = any(
            term in haystack
            for term in PlanningPipeline._NEAR_MISS_STRONG_TERMS
        )
        if has_strong_decode_signal:
            return True

        has_protocol_signal = any(
            term in haystack
            for term in PlanningPipeline._NEAR_MISS_PROTOCOL_TERMS
        )
        if has_protocol_signal:
            return False

        has_weak_decode_signal = any(
            term in haystack
            for term in PlanningPipeline._NEAR_MISS_WEAK_TERMS
        )
        if has_weak_decode_signal:
            return True

        challenge = state.metadata.get("challenge", {}) or {}
        category = str(challenge.get("category") or "").strip().lower()
        return category in PlanningPipeline._NEAR_MISS_CATEGORIES

    @staticmethod
    def _near_miss_candidate_body(near_misses: list[object]) -> str:
        bodies: list[str] = []
        for item in near_misses[:3]:
            text = str(item)
            lines = text.splitlines()
            if lines and "preview:" in lines[0].lower():
                text = "\n".join(lines[1:])
            bodies.append(text)
        return "\n".join(bodies)

    # Atomic recon families: at most one open/done todo of this family per
    # files_root.  Re-running them adds no signal beyond the first execution.
    _ATOMIC_RECON_FAMILIES = frozenset({"artifact-inventory", "recon"})

    def _dedupe(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        # A dedupe key identifies one semantic attempt.  Re-attempts must carry
        # new novelty/evidence so they produce a different key.
        seen = {
            todo.dedupe_key
            for todo in state.todos
            if todo.dedupe_key
        }
        atomic_seen: set[tuple[str, str]] = set()
        for todo in state.todos:
            family = str(todo.context.get("family") or "")
            if family in self._ATOMIC_RECON_FAMILIES and todo.phase == TodoPhase.RECON:
                atomic_seen.add((family, str(todo.context.get("files_root") or "")))
        validation_seen: set[str] = set()
        for todo in state.todos:
            if todo.phase != TodoPhase.FLAG_VALIDATION:
                continue
            if todo.status not in {
                TodoStatus.PENDING,
                TodoStatus.RUNNING,
                TodoStatus.COMPLETED,
                TodoStatus.PARTIAL,
            }:
                continue
            candidate = CandidatePolicy.first_candidate_from_context(state, todo.context, todo.goal)
            if candidate:
                validation_seen.add(candidate)
        out: list[PlannedTodo] = []
        dropped = 0
        for todo in todos:
            if not todo.dedupe_key:
                todo.dedupe_key = TodoPolicy.default_key(todo)
            if todo.dedupe_key in seen:
                dropped += 1
                continue
            family = str(todo.context.get("family") or "")
            if family in self._ATOMIC_RECON_FAMILIES and todo.phase == TodoPhase.RECON:
                atomic_key = (family, str(todo.context.get("files_root") or ""))
                if atomic_key in atomic_seen:
                    dropped += 1
                    continue
                atomic_seen.add(atomic_key)
            if todo.phase == TodoPhase.FLAG_VALIDATION:
                candidate = CandidatePolicy.first_candidate_from_context(state, todo.context, todo.goal)
                if candidate and candidate in validation_seen:
                    dropped += 1
                    continue
                if candidate:
                    validation_seen.add(candidate)
            seen.add(todo.dedupe_key)
            out.append(todo)
        notes = [f"Planning pipeline dropped {dropped} duplicate todo(s)."] if dropped else []
        return out, notes

    def _phase_gate(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        focus = self._frontier_phase(todos, state)
        if focus is None:
            return todos, []

        kept: list[PlannedTodo] = []
        phase_dropped: list[PlannedTodo] = []
        grounding_dropped: list[PlannedTodo] = []
        for todo in todos:
            if todo.phase != focus:
                phase_dropped.append(todo)
                continue
            if not self._grounded(todo, state):
                grounding_dropped.append(todo)
                continue
            kept.append(todo)

        notes: list[str] = []
        if phase_dropped:
            notes.append(
                f"Planning phase gate kept {focus.value} todos and dropped "
                f"{len(phase_dropped)} todo(s) from other phases."
            )
        if grounding_dropped:
            notes.append(
                f"Planning phase gate dropped {len(grounding_dropped)} ungrounded "
                f"{focus.value} todo(s)."
            )
        return kept, notes

    def _progress_gate(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        out: list[PlannedTodo] = []
        notes: list[str] = []
        for todo in todos:
            allowed, reason = ProgressPolicy.allows(todo, state)
            if allowed:
                out.append(todo)
            else:
                notes.append(f"Planning progress gate dropped todo: {reason}.")
        return out, notes

    def _scope_gate(
        self,
        todos: list[PlannedTodo],
        state: RunState,
    ) -> tuple[list[PlannedTodo], list[str]]:
        kept: list[PlannedTodo] = []
        dropped = 0
        challenge = state.metadata.get("challenge", {}) or {}
        challenge_files = challenge.get("files", []) if isinstance(challenge, dict) else []
        artifact_paths = [
            str(artifact.path)
            for artifact in state.artifacts.values()
            if str(getattr(artifact, "path", "") or "").strip()
        ]
        for todo in todos:
            reason = todo_loopback_block_reason(
                goal=todo.goal,
                context=todo.context or {},
                authorized_scope=state.authorized_scope,
            )
            reason = reason or todo_registered_scratch_dependency_reason(
                goal=todo.goal,
                context=todo.context or {},
                allowed_artifact_paths=artifact_paths,
            )
            reason = reason or todo_ephemeral_artifact_dependency_reason(
                goal=todo.goal,
                context=todo.context or {},
                challenge_files=challenge_files,
                files_root=(todo.context or {}).get("files_root"),
                allowed_artifact_paths=artifact_paths,
            )
            if reason:
                dropped += 1
                continue
            kept.append(todo)
        notes = [f"Planning scope gate dropped {dropped} out-of-scope todo(s)."] if dropped else []
        return kept, notes

    @staticmethod
    def _frontier_phase(todos: list[PlannedTodo], state: RunState) -> TodoPhase | None:
        open_phases = [
            todo.phase
            for todo in state.todos
            if todo.status in {TodoStatus.PENDING, TodoStatus.RUNNING}
        ]
        if open_phases:
            return min(open_phases, key=todo_phase_rank)
        if todos and CandidatePolicy.validation_ready_candidates(state):
            if any(todo.phase == TodoPhase.FLAG_VALIDATION for todo in todos):
                # Only force FLAG_VALIDATION if the family is not in cooldown
                _, failed = ProgressPolicy._family_counts(state, "flag-validation")
                if failed < ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD:
                    return TodoPhase.FLAG_VALIDATION
        if todos:
            return min((todo.phase for todo in todos), key=todo_phase_rank)
        return None

    @staticmethod
    def _grounded(todo: PlannedTodo, state: RunState) -> bool:
        context = todo.context or {}
        if todo.phase == TodoPhase.EXPLOIT:
            if state.vulnerabilities or state.credentials or state.sessions:
                return True
            return (
                ContextRefPolicy.refs_existing(
                    context,
                    state.findings,
                    "finding_id",
                    "finding_ids",
                )
                or ContextRefPolicy.refs_existing(
                    context,
                    state.vulnerabilities,
                    "vulnerability_id",
                    "vulnerability_ids",
                )
                or ContextRefPolicy.refs_existing(
                    context,
                    state.credentials,
                    "credential_id",
                    "credential_ids",
                )
                or ContextRefPolicy.refs_existing(
                    context,
                    state.sessions,
                    "session_id",
                    "session_ids",
                )
                or ContextRefPolicy.refs_existing(
                    context,
                    state.hypotheses,
                    "hypothesis_id",
                    "hypothesis_ids",
                )
                or ContextRefPolicy.refs_existing(
                    context,
                    state.evidence,
                    "evidence_id",
                    "evidence_ids",
                )
                or PlanningPipeline._refs_observed_endpoint(context, state)
            )
        if todo.phase == TodoPhase.FLAG_VALIDATION:
            return CandidatePolicy.first_candidate_from_context(state, context, todo.goal) is not None
        return True

    @staticmethod
    def _refs_observed_endpoint(context: dict, state: RunState) -> bool:
        if ContextRefPolicy.refs_existing(
            context,
            state.endpoints,
            "endpoint_id",
            "endpoint_ids",
        ):
            return True

        observed = [
            endpoint
            for endpoint in state.endpoints.values()
            if PlanningPipeline._endpoint_has_positive_observation(endpoint)
        ]
        if not observed:
            return False

        for endpoint in observed:
            if PlanningPipeline._endpoint_url_matches(context, endpoint):
                return True
            if PlanningPipeline._endpoint_host_port_matches(context, endpoint):
                return True
        return False

    @staticmethod
    def _endpoint_has_positive_observation(endpoint) -> bool:
        if endpoint.status_code is not None:
            return True
        if endpoint.metadata:
            return True
        protocol = str(endpoint.protocol or "").lower()
        return bool(endpoint.hostname and endpoint.port and protocol not in {"", "http", "https"})

    @staticmethod
    def _endpoint_url_matches(context: dict, endpoint) -> bool:
        for raw in ContextRefPolicy.values(context, "url", "base_url", "scope"):
            parsed = PlanningPipeline._parse_endpoint_ref(raw)
            if parsed is None:
                continue
            hostname, port = parsed
            if PlanningPipeline._same_endpoint(endpoint, hostname, port):
                return True
        return False

    @staticmethod
    def _endpoint_host_port_matches(context: dict, endpoint) -> bool:
        hosts = {
            value.lower()
            for value in ContextRefPolicy.values(context, "host", "hostname", "server_name")
        }
        ports = ContextRefPolicy.values(context, "port", "ports")
        if not hosts or not ports:
            return False
        endpoint_host = str(endpoint.hostname or "").lower()
        endpoint_port = str(endpoint.port or "")
        return endpoint_host in hosts and endpoint_port in ports

    @staticmethod
    def _parse_endpoint_ref(raw: object) -> tuple[str, int | None] | None:
        text = str(raw or "").strip()
        if not text:
            return None
        candidate = text if "://" in text else f"//{text}"
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return None
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443
        return hostname, port

    @staticmethod
    def _same_endpoint(endpoint, hostname: str, port: int | None) -> bool:
        if str(endpoint.hostname or "").lower() != hostname:
            return False
        return port is None or endpoint.port == port
