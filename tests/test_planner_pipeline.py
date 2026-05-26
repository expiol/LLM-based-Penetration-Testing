"""Tests for the high-level planner pipeline."""

from __future__ import annotations
import json
import unittest
from killchain_docker.rag.augmenter import RagAugmenter
from killchain_docker.llm.gateway import LLMClientError, StaticLLMClient
from killchain_docker.orchestrator.todo_queue import TodoQueue as todo_queue
from killchain_docker.orchestrator.planning.pipeline import PlanningPipeline
from killchain_docker.orchestrator.planning.planner import LLMPlanner
from killchain_docker.orchestrator.planning.schemas import PlannedTodo, PlannerDecision
from killchain_docker.orchestrator.planning.techniques import technique_matrix_for
from killchain_docker.orchestrator.todo_family import family_for
from killchain_docker.orchestrator.todo_normalization import normalize_todo
from killchain_docker.state.evidence_facts import EvidenceFactStore
from killchain_docker.state.recon_facts import ReconFactStore
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.domain import (
    Artifact,
    Credential,
    EvidenceRecord,
    Endpoint,
    ExecutionRecord,
    Finding,
    FlagCandidate,
    Hypothesis,
    Severity,
    Session,
    StateDelta,
    Vulnerability,
)
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, WorkerResult
from killchain_docker.state.state_delta import StateDeltaApplier
from killchain_docker.state.worker_results import WorkerResultApplier


def _state(files: list[str] | None = None, scope: list[str] | None = None) -> RunState:
    return RunState(
        objective="Solve test challenge.",
        authorized_scope=list(scope or []),
        metadata={
            "challenge": {
                "name": "test",
                "category": "crypto",
                "flag_format": "flag{...}",
                "files": list(files or []),
            }
        },
    )


def _capability(todo: PlannedTodo | TodoItem) -> str:
    intent = todo.context.get("dispatch_intent")
    if isinstance(intent, dict):
        return str(intent.get("required_capability") or "")
    return ""


class PlanningPipelineSeedTests(unittest.TestCase):
    def test_seed_artifacts_and_scope_as_high_level_todos(self) -> None:
        state = _state(["solve.py"], ["http://example.test"])
        decision = PlanningPipeline().plan(state)
        goals = [todo.goal for todo in decision.todos]
        self.assertTrue(any(("Inventory" in goal for goal in goals)))
        self.assertTrue(any(("Map authorized scope" in goal for goal in goals)))
        self.assertTrue(
            all((not hasattr(todo, "task_type") for todo in decision.todos))
        )

    def test_seed_flag_validation_for_grounded_candidate(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        decision = PlanningPipeline().plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(decision.todos[0].context["candidate_flag"], "flag{okay}")

    def test_seed_validates_one_highest_confidence_candidate_at_a_time(self) -> None:
        state = _state([])
        low = FlagCandidate(
            value="flag{candidate_low}", source="script", confidence=0.2
        )
        high = FlagCandidate(
            value="flag{candidate_high}", source="script", confidence=0.9
        )
        state.flag_candidates[low.candidate_id] = low
        state.flag_candidates[high.candidate_id] = high
        decision = PlanningPipeline().plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(
            decision.todos[0].context["candidate_flag"], "flag{candidate_high}"
        )

    def test_seed_candidate_recovery_from_validator_rejection(self) -> None:
        state = _state(["cipher.bin"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "done")
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                evidence_id="evidence-candidate",
                task_id=inventory.todo_id,
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="Candidate was derived from local artifact evidence.",
            )
        )
        RunJournal(state).rejected_flag_candidate(
            value="flag{almost}",
            reason="candidate_mismatch",
            source="flag-worker",
            evidence_refs=["evidence-candidate"],
        )
        decision = PlanningPipeline().plan(state)
        recovery = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "candidate-recovery"
            )
        )
        self.assertEqual(recovery.phase, TodoPhase.ANALYSIS)
        self.assertEqual(recovery.context["recovery_trigger"], "validator_rejection")
        self.assertEqual(recovery.context["evidence_ids"], ["evidence-candidate"])
        self.assertEqual(recovery.context["flag_format_prefix"], "flag{")
        self.assertEqual(recovery.context["challenge_files"], ["cipher.bin"])
        self.assertTrue(
            str(recovery.dedupe_key).startswith("bootstrap:candidate-recovery:")
        )
        text = " ".join(
            [
                recovery.goal,
                *recovery.success_criteria,
                *recovery.constraints,
                json.dumps(recovery.context, sort_keys=True),
            ]
        ).lower()
        for disallowed in ("oracle", "rag", "benchmark", "zbar", "sleuth", "foremost"):
            self.assertNotIn(disallowed, text)

    def test_candidate_recovery_waits_for_ready_validation_candidate(self) -> None:
        state = _state([])
        RunJournal(state).rejected_flag_candidate(
            value="flag{almost}", reason="candidate_mismatch", source="flag-worker"
        )
        candidate = FlagCandidate(value="flag{fixed}", source="policy")
        state.flag_candidates[candidate.candidate_id] = candidate
        decision = PlanningPipeline().plan(state)
        self.assertTrue(
            any((todo.phase == TodoPhase.FLAG_VALIDATION for todo in decision.todos))
        )
        self.assertFalse(
            any(
                (
                    todo.context.get("family") == "candidate-recovery"
                    for todo in decision.todos
                )
            )
        )

    def test_seed_execution_closure_after_inventory(self) -> None:
        state = _state(["capture.bin"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={
                    "family": "artifact-inventory",
                    "files_root": "/home/ctfplayer/ctf_files",
                },
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "done")
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="no extra todos", todos=[])
        )
        self.assertEqual(len(decision.todos), 1)
        todo = decision.todos[0]
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertEqual(todo.context["family"], "algorithm-verification")
        self.assertEqual(_capability(todo), "script.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )
        self.assertNotIn("knowledge_hint_ranks", todo.context)
        text = " ".join([todo.goal, *todo.success_criteria, *todo.constraints]).lower()
        self.assertNotIn("oracle", text)
        self.assertNotIn("rag", text)

    def test_execution_closure_seed_waits_for_artifact_inventory(self) -> None:
        state = _state(["capture.bin"])
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="no extra todos", todos=[])
        )
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].dedupe_key, "bootstrap:artifact-inventory")
        self.assertNotIn("execution_closure", decision.todos[0].context)

    def test_execution_closure_seed_does_not_mask_llm_analysis_todo(self) -> None:
        state = _state(["capture.bin"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "done")
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="inspect bytes",
                todos=[
                    PlannedTodo(
                        goal="Review file metadata and note next leads.",
                        phase=TodoPhase.ANALYSIS,
                        context={"family": "artifact-followup"},
                        success_criteria=["Produce a concrete diagnostic."],
                    )
                ],
            ),
        )
        keys = {todo.dedupe_key for todo in decision.todos}
        self.assertNotIn("bootstrap:evidence-execution-closure", keys)
        self.assertTrue(
            all((todo.phase == TodoPhase.ANALYSIS for todo in decision.todos))
        )

    def test_seed_generated_unclassified_artifact_followup_uses_triage_hint(
        self,
    ) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/out.random",
            kind="script_artifact",
            source="script_exec",
            size=4096,
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertEqual(followup.phase, TodoPhase.ANALYSIS)
        self.assertEqual(_capability(followup), "artifact.triage")
        self.assertEqual(followup.context["path"], artifact.path)
        self.assertTrue(
            str(followup.dedupe_key).startswith("bootstrap:artifact-followup:")
        )

    def test_seed_generated_confirmed_png_artifact_followup_uses_png_inspect_hint(
        self,
    ) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/work/out.png",
            kind="script_artifact_png",
            source="script_exec",
            size=4096,
            digest="a" * 64,
            metadata={
                "file_type": "PNG image data, 1 x 1, 8-bit/color RGBA",
                "mime_type": "image/png",
                "origin": "work",
            },
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertEqual(followup.phase, TodoPhase.ANALYSIS)
        self.assertEqual(_capability(followup), "png.inspect")
        self.assertEqual(followup.context["path"], artifact.path)

    def test_script_generated_media_artifact_followups_are_batched(self) -> None:
        state = _state([])
        artifacts = [
            Artifact(
                path=f"/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/out{index}",
                kind="script_artifact",
                source="script_exec",
                size=4096,
                digest=f"media-{index}",
                metadata={"mime_type": mime_type},
            )
            for index, mime_type in enumerate(("image/jpeg", "image/gif", "image/bmp"))
        ]
        for artifact in artifacts:
            state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followups = [
            todo
            for todo in decision.todos
            if todo.context.get("family") == "artifact-followup"
        ]
        self.assertEqual(len(followups), 1)
        followup = followups[0]
        self.assertEqual(_capability(followup), "media.scan")
        self.assertEqual(
            followup.context["paths"], [artifact.path for artifact in artifacts]
        )
        self.assertNotIn("path", followup.context)

    def test_script_generated_png_keeps_png_inspect_when_other_media_are_batched(
        self,
    ) -> None:
        state = _state([])
        png = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/out0",
            kind="script_artifact",
            source="script_exec",
            size=4096,
            digest="png-digest",
            metadata={"mime_type": "image/png"},
        )
        jpeg = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/out1",
            kind="script_artifact",
            source="script_exec",
            size=4096,
            digest="jpeg-digest",
            metadata={"mime_type": "image/jpeg"},
        )
        state.artifacts[png.artifact_id] = png
        state.artifacts[jpeg.artifact_id] = jpeg
        decision = PlanningPipeline().plan(state)
        png_followup = next(
            (todo for todo in decision.todos if _capability(todo) == "png.inspect")
        )
        media_followup = next(
            (todo for todo in decision.todos if _capability(todo) == "media.scan")
        )
        self.assertEqual(png_followup.context["path"], png.path)
        self.assertEqual(media_followup.context["path"], jpeg.path)
        self.assertEqual(media_followup.context["paths"], [jpeg.path])

    def test_generated_source_tree_docs_png_uses_content_followup(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/project/docs/assets/img/profiler.png",
            kind="script_artifact_png",
            source="script_exec",
            size=4096,
            digest="docs-png",
            metadata={
                "origin": "scratch",
                "relative_path": "project/docs/assets/img/profiler.png",
                "file_type": "PNG image data, 1181 x 829, 8-bit/color RGBA",
                "mime_type": "image/png",
            },
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
                and todo.context.get("path") == artifact.path
            )
        )
        self.assertEqual(_capability(followup), "png.inspect")

    def test_generated_source_tree_framework_font_does_not_seed_followup(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/project/public/assets/fonts/glyphicons-halflings-regular.woff",
            kind="script_artifact",
            source="script_exec",
            size=16448,
            digest="font",
            metadata={
                "origin": "scratch",
                "relative_path": "project/public/assets/fonts/glyphicons-halflings-regular.woff",
                "file_type": "Web Open Font Format, TrueType",
                "mime_type": "application/octet-stream",
            },
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    todo.context.get("family") == "artifact-followup"
                    and todo.context.get("path") == artifact.path
                    for todo in decision.todos
                )
            )
        )

    def test_ooxml_child_artifact_seeds_office_inspect_hint(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/offset_0/deck.pptx",
            kind="disk_extract_document",
            source="disk_extract",
            metadata={
                "file_type": "Microsoft PowerPoint 2007+",
                "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            },
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertEqual(_capability(followup), "office.inspect")
        self.assertEqual(followup.context["path"], artifact.path)

    def test_office_media_artifact_seeds_media_scan_hint(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/office/ppt/media/image28.png",
            kind="office_media_image",
            source="office_inspect",
            metadata={"mime_type": "image/png"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertEqual(_capability(followup), "media.scan")
        self.assertEqual(followup.context["path"], artifact.path)
        self.assertEqual(followup.context["paths"], [artifact.path])
        self.assertEqual(followup.priority, 90)

    def test_suspicious_media_scan_png_seeds_png_inspect(self) -> None:
        state = _state([])
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/office/ppt/media/image28.png"
        artifact = Artifact(
            path=path,
            kind="office_media_image",
            source="office_inspect",
            digest="d" * 64,
            metadata={"mime_type": "image/png"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        media_todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Batch-scan embedded media artifacts deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "dispatch_intent": {
                        "profile": "media_inspection",
                        "required_capability": "media.scan",
                    },
                    "path": path,
                },
                dedupe_key="media-scan-once",
            )
        )
        todo_queue(state).start(media_todo, "artifact-worker")
        todo_queue(state).complete(
            media_todo, "media.scan: 1 file(s) inspected, 1 suspicious"
        )
        evidence = EvidenceRecord(
            task_id=media_todo.todo_id,
            capability="media.scan",
            tool_name="media_scan",
            mode="local_command",
            summary="media.scan: 1 file(s) inspected, 1 suspicious",
            extracted={
                "output_context": {
                    "media": [
                        {
                            "path": path,
                            "kind": "png",
                            "suspicious": True,
                            "strings": "key fragment",
                        }
                    ]
                }
            },
        )
        state.evidence[evidence.evidence_id] = evidence
        decision = PlanningPipeline().plan(state)
        followups = [
            todo for todo in decision.todos if _capability(todo) == "png.inspect"
        ]
        self.assertEqual(len(followups), 1)
        followup = followups[0]
        self.assertEqual(followup.context["path"], path)
        self.assertEqual(followup.context["artifact_id"], artifact.artifact_id)
        self.assertEqual(followup.context["evidence_ids"], [evidence.evidence_id])
        self.assertEqual(
            followup.dedupe_key, f"bootstrap:suspicious-png-inspect:{'d' * 64}"
        )

    def test_suspicious_media_scan_skips_png_already_inspected(self) -> None:
        state = _state([])
        queue = todo_queue(state)
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/office/ppt/media/image28.png"
        inspected = queue.enqueue(
            TodoItem(
                goal="Inspect suspicious PNG media artifact deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "dispatch_intent": {
                        "profile": "image_inspection",
                        "required_capability": "png.inspect",
                    },
                    "path": path,
                },
                dedupe_key="png-inspect-once",
            )
        )
        queue.complete(inspected, "png.inspect: done")
        evidence = EvidenceRecord(
            task_id="todo-media",
            capability="media.scan",
            tool_name="media_scan",
            mode="local_command",
            summary="media.scan: 1 file(s) inspected, 1 suspicious",
            extracted={
                "output_context": {
                    "media": [{"path": path, "kind": "png", "suspicious": True}]
                }
            },
        )
        state.evidence[evidence.evidence_id] = evidence
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    _capability(todo) == "png.inspect"
                    and todo.context.get("path") == path
                    for todo in decision.todos
                )
            )
        )

    def test_suspicious_png_followup_can_pass_artifact_family_hard_cap(self) -> None:
        state = _state([])
        for index in range(10):
            todo = todo_queue(state).enqueue(
                TodoItem(
                    goal=f"Prior artifact follow-up {index}",
                    phase=TodoPhase.ANALYSIS,
                    context={
                        "family": "artifact-followup",
                        "dispatch_intent": {
                            "profile": "artifact_analysis",
                            "required_capability": "artifact.triage",
                        },
                        "path": f"/home/ctfplayer/ctf_files/.autopentest_artifacts/prior/{index}.bin",
                    },
                    dedupe_key=f"prior-artifact-followup-{index}",
                )
            )
            todo_queue(state).complete(todo, "artifact.triage done")
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/office/ppt/media/image28.png"
        artifact = Artifact(
            path=path,
            kind="office_media_image",
            source="office_inspect",
            digest="9" * 64,
            metadata={"mime_type": "image/png"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        evidence = EvidenceRecord(
            task_id="todo-media",
            capability="media.scan",
            tool_name="media_scan",
            mode="local_command",
            summary="media.scan: 1 file(s) inspected, 1 suspicious",
            extracted={
                "output_context": {
                    "media": [{"path": path, "kind": "png", "suspicious": True}]
                }
            },
        )
        state.evidence[evidence.evidence_id] = evidence
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(summary="backlog seed refresh", todos=[]),
        )
        self.assertTrue(
            any(
                (
                    _capability(todo) == "png.inspect"
                    and todo.context.get("path") == path
                    for todo in decision.todos
                )
            )
        )

    def test_generated_artifact_followup_with_evidence_passes_family_hard_cap(
        self,
    ) -> None:
        state = _state([])
        for index in range(12):
            todo = todo_queue(state).enqueue(
                TodoItem(
                    goal=f"Prior artifact follow-up {index}",
                    phase=TodoPhase.ANALYSIS,
                    context={
                        "family": "artifact-followup",
                        "dispatch_intent": {
                            "profile": "artifact_analysis",
                            "required_capability": "artifact.triage",
                        },
                        "path": f"/home/ctfplayer/ctf_files/.autopentest_artifacts/prior/{index}.bin",
                    },
                    dedupe_key=f"prior-artifact-followup-{index}",
                )
            )
            todo_queue(state).complete(todo, "artifact.triage done")
        evidence = EvidenceRecord(
            task_id="todo-png",
            capability="png.inspect",
            tool_name="png_inspect",
            mode="local_command",
            summary="png.inspect generated LSB artifacts",
        )
        state.evidence[evidence.evidence_id] = evidence
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image/lsb_all_2_msb.bin",
            kind="png_inspect_lsb",
            source="png_inspect",
            digest="lsb-digest",
            metadata={"evidence_ids": [evidence.evidence_id]},
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="final seed refresh", todos=[])
        )
        followup = next(
            (
                todo
                for todo in decision.todos
                if _capability(todo) == "artifact.triage"
                and todo.context.get("path") == artifact.path
            )
        )
        self.assertEqual(followup.context["evidence_ids"], [evidence.evidence_id])

    def test_llm_abstract_media_analyze_for_png_dedupes_to_png_inspect(self) -> None:
        state = _state([])
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/office/ppt/media/image19.png"
        artifact = Artifact(
            path=path,
            kind="office_media_image",
            source="office_inspect",
            digest="f" * 64,
            metadata={"mime_type": "image/png"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        media_todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Batch-scan embedded media artifacts deterministically.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "artifact-followup",
                    "dispatch_intent": {
                        "profile": "media_inspection",
                        "required_capability": "media.scan",
                    },
                    "path": path,
                },
                dedupe_key="media-scan-once",
            )
        )
        todo_queue(state).complete(media_todo, "media.scan: suspicious PNG")
        evidence = EvidenceRecord(
            task_id=media_todo.todo_id,
            capability="media.scan",
            tool_name="media_scan",
            mode="local_command",
            summary="media.scan: 1 file(s) inspected, 1 suspicious",
            extracted={
                "output_context": {
                    "media": [{"path": path, "kind": "png", "suspicious": True}]
                }
            },
        )
        state.evidence[evidence.evidence_id] = evidence
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="deep image analysis",
                todos=[
                    PlannedTodo(
                        goal="Perform detailed steganography analysis on image19.png.",
                        phase=TodoPhase.ANALYSIS,
                        priority=95,
                        context={
                            "family": "forensics-extract",
                            "dispatch_intent": {
                                "profile": "image_inspection",
                                "required_capability": "png.inspect",
                            },
                            "path": path,
                        },
                        dedupe_key="stego-image19-analysis",
                    )
                ],
            ),
        )
        png_todos = [
            todo
            for todo in decision.todos
            if todo.context.get("path") == path and _capability(todo) == "png.inspect"
        ]
        self.assertEqual(len(png_todos), 1)
        self.assertEqual(png_todos[0].dedupe_key, f"bootstrap:artifact-followup:{path}")
        self.assertFalse(
            any((_capability(todo) == "media.analyze" for todo in decision.todos))
        )

    def test_llm_source_code_analysis_alias_is_not_suffix_rewritten(self) -> None:
        state = _state(["solver.random"])
        queue = todo_queue(state)
        inventory = queue.enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        queue.complete(inventory, "done")
        path = "/home/ctfplayer/ctf_files/solver.random"
        artifact = Artifact(path=path, kind="script_artifact", source="artifact_triage")
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="read source",
                todos=[
                    PlannedTodo(
                        goal="Analyze the referenced source to extract constants, ciphertext arrays, and algorithm order.",
                        phase=TodoPhase.ANALYSIS,
                        priority=90,
                        context={
                            "family": "artifact-followup",
                            "dispatch_intent": {
                                "profile": "artifact_analysis",
                                "required_capability": "source.code_analysis",
                            },
                            "artifact_id": artifact.artifact_id,
                            "artifact_path": path,
                            "source_file": "solver.random",
                            "files_root": "/home/ctfplayer/ctf_files",
                        },
                    )
                ],
            ),
        )
        todo = next(
            (
                item
                for item in decision.todos
                if item.context.get("artifact_path") == path
            )
        )
        self.assertEqual(todo.context["family"], "artifact-followup")
        self.assertEqual(_capability(todo), "source.code_analysis")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"],
            "source.code_analysis",
        )

    def test_generated_binary_artifact_followup_does_not_crowd_analysis(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image6_1050/lsb_all_2_msb.bin",
            kind="png_inspect_lsb",
            source="png_inspect",
            digest="b" * 64,
            metadata={"png_role": "lsb", "source_entry": "all:2:msb"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertEqual(_capability(followup), "artifact.triage")
        self.assertLess(followup.priority, 90)

    def test_generated_binary_artifact_followups_are_batched(self) -> None:
        state = _state([])
        for index in range(10):
            artifact = Artifact(
                path=f"/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image6_1050/lsb_all_{index}_msb.bin",
                kind="png_inspect_lsb",
                source="png_inspect",
                digest=f"batch-{index}",
                metadata={"png_role": "lsb", "source_entry": f"all:{index}:msb"},
            )
            state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followups = [
            todo
            for todo in decision.todos
            if todo.context.get("family") == "artifact-followup"
        ]
        self.assertEqual(len(followups), 2)
        self.assertEqual(_capability(followups[0]), "artifact.triage")
        self.assertEqual(len(followups[0].context["paths"]), 8)
        self.assertEqual(len(followups[1].context["paths"]), 2)
        self.assertTrue(
            all(
                (
                    str(todo.dedupe_key).startswith(
                        "bootstrap:artifact-followup-batch:"
                    )
                    for todo in followups
                )
            )
        )

    def test_artifact_followup_seed_fanout_is_bounded(self) -> None:
        state = _state([])
        for index in range(20):
            artifact = Artifact(
                path=f"/home/ctfplayer/ctf_files/.autopentest_artifacts/office_inspect_deck/ppt/media/image{index}.png",
                kind="office_media_image",
                source="office_inspect",
                digest=f"sha256-{index}",
            )
            state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followups = [
            todo
            for todo in decision.todos
            if todo.context.get("family") == "artifact-followup"
        ]
        self.assertEqual(len(followups), 2)
        self.assertTrue(all((_capability(todo) == "media.scan" for todo in followups)))
        self.assertEqual(len(followups[0].context["paths"]), 12)
        self.assertEqual(len(followups[1].context["paths"]), 8)
        self.assertTrue(any(("batched media scan" in note for note in decision.notes)))

    def test_candidate_recovery_outranks_generated_artifact_followup(self) -> None:
        state = _state(["out.img"])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image6_1050/lsb_all_2_msb.bin",
            kind="png_inspect_lsb",
            source="png_inspect",
            digest="c" * 64,
        )
        state.artifacts[artifact.artifact_id] = artifact
        RunJournal(state).rejected_flag_candidate(
            value="flag{wrong}", reason="candidate_mismatch", source="validator"
        )
        decision = PlanningPipeline().plan(state)
        recovery = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "candidate-recovery"
            )
        )
        followup = next(
            (
                todo
                for todo in decision.todos
                if todo.context.get("family") == "artifact-followup"
            )
        )
        self.assertGreater(recovery.priority, followup.priority)

    def test_artifact_triage_source_does_not_seed_followup_loop(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/out.png",
            kind="image",
            source="artifact_triage",
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    todo.context.get("family") == "artifact-followup"
                    for todo in decision.todos
                )
            )
        )

    def test_disk_image_artifact_seeds_disk_extract_hint(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/out.img",
            kind="unknown",
            source="artifact_triage",
            metadata={"file_type": "DOS/MBR boot sector"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        disk_extract = next(
            (todo for todo in decision.todos if _capability(todo) == "disk.extract")
        )
        self.assertEqual(disk_extract.phase, TodoPhase.ANALYSIS)
        self.assertEqual(disk_extract.context["family"], "forensics-extract")
        self.assertEqual(disk_extract.context["path"], artifact.path)
        self.assertTrue(
            str(disk_extract.dedupe_key).startswith("bootstrap:disk-extract:")
        )

    def test_llm_disk_extract_duplicate_dedupes_against_seed(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/out.img",
            kind="unknown",
            source="artifact_triage",
            metadata={"file_type": "DOS/MBR boot sector"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="extract disk",
                todos=[
                    PlannedTodo(
                        goal="Extract files from the detected disk image.",
                        phase=TodoPhase.ANALYSIS,
                        priority=90,
                        context={
                            "family": "forensics-extract",
                            "dispatch_intent": {
                                "profile": "container_extraction",
                                "required_capability": "disk.extract",
                            },
                            "path": artifact.path,
                        },
                    )
                ],
            ),
        )
        disk_extracts = [
            todo for todo in decision.todos if _capability(todo) == "disk.extract"
        ]
        self.assertEqual(len(disk_extracts), 1)
        self.assertTrue(any(("duplicate" in note for note in decision.notes)))

    def test_llm_disk_extract_without_context_resolves_unique_disk_artifact(
        self,
    ) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/out.img",
            kind="unknown",
            source="artifact_triage",
            metadata={"file_type": "DOS/MBR boot sector"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        existing = todo_queue(state).enqueue(
            TodoItem(
                goal="Extract files from the detected disk image.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "forensics-extract",
                    "dispatch_intent": {
                        "profile": "container_extraction",
                        "required_capability": "disk.extract",
                    },
                    "path": artifact.path,
                },
                dedupe_key=f"bootstrap:disk-extract:{artifact.path}",
            )
        )
        todo_queue(state).start(existing, "artifact-worker")
        todo_queue(state).complete(existing, "disk.extract done")
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="extract embedded zip",
                todos=[
                    PlannedTodo(
                        goal="Analyze the disk image structure and extract embedded ZIP archive at offset 0x4A400.",
                        phase=TodoPhase.RECON,
                        priority=90,
                        context={"family": "other"},
                        dedupe_key="extract-embedded-zip",
                    )
                ],
            ),
        )
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("duplicate" in note for note in decision.notes)))

    def test_png_triage_child_artifact_seeds_followup(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/png_triage/out.png/001_qfme.bin",
            kind="png_chunk_qfme",
            source="artifact_triage_png",
        )
        state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        followups = [
            todo
            for todo in decision.todos
            if todo.context.get("family") == "artifact-followup"
        ]
        self.assertEqual(len(followups), 1)
        self.assertEqual(followups[0].context["path"], artifact.path)

    def test_disk_extract_followup_skips_low_signal_os_metadata(self) -> None:
        state = _state([])
        doc = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/offset_0/clam.pptx",
            kind="disk_extract_document",
            source="disk_extract",
            metadata={
                "file_type": "Microsoft PowerPoint 2007+",
                "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            },
        )
        index = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/offset_0/Spotlight-V100/Store-V2/0.indexHead",
            kind="disk_extract_indexhead",
            source="disk_extract",
            metadata={"role": "os_metadata", "file_type": "data"},
        )
        state.artifacts[doc.artifact_id] = doc
        state.artifacts[index.artifact_id] = index
        decision = PlanningPipeline().plan(state)
        paths = [
            todo.context.get("path")
            for todo in decision.todos
            if todo.context.get("family") == "artifact-followup"
        ]
        self.assertEqual(paths, [doc.path])
        self.assertEqual(
            next(
                (
                    _capability(todo)
                    for todo in decision.todos
                    if todo.context.get("family") == "artifact-followup"
                )
            ),
            "office.inspect",
        )

    def test_disk_extract_children_do_not_seed_recursive_disk_extract_from_kind_prefix(
        self,
    ) -> None:
        state = _state([])
        artifacts = [
            Artifact(
                path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk/offset_0/store",
                kind="disk_extract_database",
                source="disk_extract",
                metadata={"file_type": "data"},
            ),
            Artifact(
                path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk/offset_0/index",
                kind="disk_extract_indexhead",
                source="disk_extract",
                metadata={"file_type": "data"},
            ),
            Artifact(
                path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk/offset_0/notes",
                kind="disk_extract_file",
                source="disk_extract",
                metadata={"file_type": "ASCII text"},
            ),
        ]
        for artifact in artifacts:
            state.artifacts[artifact.artifact_id] = artifact
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    _capability(todo) == "disk.extract"
                    and todo.context.get("path")
                    in {artifact.path for artifact in artifacts}
                    for todo in decision.todos
                )
            )
        )

    def test_artifact_followup_skips_path_already_executed_by_llm_tool(self) -> None:
        state = _state([])
        doc = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/offset_0/clam.pptx",
            kind="disk_extract_document",
            source="disk_extract",
            digest="e" * 64,
            metadata={
                "file_type": "Microsoft PowerPoint 2007+",
                "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            },
        )
        state.artifacts[doc.artifact_id] = doc
        prior = todo_queue(state).enqueue(
            TodoItem(
                goal="Examine the PowerPoint file for hidden objects.",
                phase=TodoPhase.ANALYSIS,
                context={"family": "forensics-extract"},
                dedupe_key="llm-office-inspect",
            )
        )
        prior.context["executed_capability"] = "office.inspect"
        prior.context["executed_path"] = doc.path
        todo_queue(state).complete(prior, "office.inspect done")
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    todo.context.get("path") == doc.path
                    and _capability(todo) == "office.inspect"
                    for todo in decision.todos
                )
            )
        )

    def test_llm_office_extract_alias_dedupes_against_artifact_followup(self) -> None:
        state = _state([])
        doc = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/embedded/zip_4f7c00.pptx",
            kind="disk_extract_document",
            source="disk_extract",
            digest="4" * 64,
            metadata={
                "file_type": "Microsoft PowerPoint 2007+",
                "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            },
        )
        state.artifacts[doc.artifact_id] = doc
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="inspect extracted presentation",
                todos=[
                    PlannedTodo(
                        goal="Analyze the extracted PowerPoint file for hidden content.",
                        phase=TodoPhase.ANALYSIS,
                        priority=50,
                        context={
                            "family": "source-review",
                            "dispatch_intent": {
                                "profile": "office_inspection",
                                "required_capability": "office.inspect",
                            },
                            "artifact_id": doc.artifact_id,
                            "artifact_path": doc.path,
                            "files_root": "/home/ctfplayer/ctf_files",
                        },
                        dedupe_key=f"pptx-analysis:{doc.artifact_id}",
                    )
                ],
            ),
        )
        office_todos = [
            todo
            for todo in decision.todos
            if todo.context.get("path") == doc.path
            and _capability(todo) == "office.inspect"
        ]
        self.assertEqual(len(office_todos), 1)
        self.assertEqual(office_todos[0].context["family"], "artifact-followup")
        self.assertEqual(
            office_todos[0].dedupe_key, f"bootstrap:artifact-followup:{doc.path}"
        )
        self.assertTrue(any(("duplicate" in note for note in decision.notes)))

    def test_bound_office_artifact_extract_goal_is_not_rewritten_to_disk_extract(
        self,
    ) -> None:
        state = _state([])
        doc = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/embedded/payload",
            kind="disk_extract_document",
            source="disk_extract",
            digest="5" * 64,
            metadata={
                "file_type": "Microsoft PowerPoint 2007+",
                "mime_type": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            },
        )
        state.artifacts[doc.artifact_id] = doc
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="extract embedded document text",
                todos=[
                    PlannedTodo(
                        goal="Extract all text and metadata from the embedded zip to recover readable evidence.",
                        phase=TodoPhase.ANALYSIS,
                        priority=80,
                        context={
                            "family": "forensics-extract",
                            "artifact_id": doc.artifact_id,
                            "artifact_path": doc.path,
                            "files_root": "/home/ctfplayer/ctf_files",
                        },
                    )
                ],
            ),
        )
        matching = [
            todo
            for todo in decision.todos
            if todo.context.get("path") == doc.path
            or todo.context.get("artifact_path") == doc.path
        ]
        self.assertTrue(
            any((_capability(todo) == "office.inspect" for todo in matching))
        )
        self.assertFalse(
            any((_capability(todo) == "disk.extract" for todo in matching))
        )

    def test_worker_result_records_executed_tool_target_for_dedupe(self) -> None:
        state = _state([])
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/disk_extract/offset_0/clam.pptx"
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Examine the PowerPoint file for hidden objects.",
                phase=TodoPhase.ANALYSIS,
                context={"family": "forensics-extract"},
                dedupe_key="llm-office-inspect",
            )
        )
        todo_queue(state).start(todo, "artifact-worker")
        WorkerResultApplier(state).apply(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="artifact-worker",
                success=True,
                summary="office.inspect done",
                output_context={"capability": "office.inspect", "path": path},
            )
        )
        self.assertEqual(todo.context["executed_capability"], "office.inspect")
        self.assertEqual(todo.context["executed_path"], path)

    def test_worker_result_annotates_generated_artifact_with_evidence_refs(
        self,
    ) -> None:
        state = _state([])
        path = "/home/ctfplayer/ctf_files/.autopentest_artifacts/png_inspect_image/lsb_all_2_msb.bin"
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Inspect PNG",
                phase=TodoPhase.ANALYSIS,
                context={"family": "artifact-followup"},
                dedupe_key="png-inspect",
            )
        )
        todo_queue(state).start(todo, "artifact-worker")
        evidence = EvidenceRecord(
            task_id=todo.todo_id,
            capability="png.inspect",
            tool_name="png_inspect",
            mode="local_command",
            summary="png.inspect generated LSB artifacts",
        )
        WorkerResultApplier(state).apply(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="artifact-worker",
                success=True,
                summary="png.inspect done",
                output_context={"capability": "png.inspect", "path": "/tmp/source.png"},
                evidence_updates=[evidence],
                state_delta=StateDelta(
                    artifacts=[
                        Artifact(
                            path=path, kind="png_inspect_lsb", source="png_inspect"
                        )
                    ]
                ),
            )
        )
        artifact = next(iter(state.artifacts.values()))
        self.assertEqual(artifact.metadata["evidence_ids"], [evidence.evidence_id])
        self.assertEqual(artifact.metadata["source_task_id"], todo.todo_id)
        self.assertEqual(artifact.metadata["source_worker"], "artifact-worker")
        self.assertEqual(artifact.metadata["source_capability"], "png.inspect")

    def test_scope_gate_drops_loopback_todo_when_scope_is_remote(self) -> None:
        state = _state([], ["tcp://remote.example:8000"])
        seed = todo_queue(state).enqueue(
            TodoItem(
                goal="Map authorized scope entry 1.",
                phase=TodoPhase.RECON,
                context={"scope": "tcp://remote.example:8000", "family": "recon"},
                dedupe_key="bootstrap:scope:tcp://remote.example:8000",
            )
        )
        todo_queue(state).complete(seed, "done")
        llm_decision = PlannerDecision(
            summary="Try the local listener.",
            todos=[
                PlannedTodo(
                    goal="Connect to localhost:8000 and solve the protocol.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={
                        "scope": "tcp://localhost:8000",
                        "family": "network-protocol",
                    },
                    success_criteria=["Capture service prompt."],
                    constraints=["Stay in scope."],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertFalse(
            any(("decrypted_flag.png" in todo.goal for todo in decision.todos))
        )
        self.assertTrue(any(("scope gate dropped" in note for note in decision.notes)))

    def test_scope_gate_allows_loopback_when_explicitly_authorized(self) -> None:
        state = _state([], ["tcp://localhost:8000"])
        seed = todo_queue(state).enqueue(
            TodoItem(
                goal="Map authorized scope entry 1.",
                phase=TodoPhase.RECON,
                context={"scope": "tcp://localhost:8000", "family": "recon"},
                dedupe_key="bootstrap:scope:tcp://localhost:8000",
            )
        )
        todo_queue(state).complete(seed, "done")
        llm_decision = PlannerDecision(
            summary="Use authorized local listener.",
            todos=[
                PlannedTodo(
                    goal="Connect to localhost:8000 and solve the protocol.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={
                        "scope": "tcp://localhost:8000",
                        "family": "network-protocol",
                    },
                    success_criteria=["Capture service prompt."],
                    constraints=["Stay in scope."],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertEqual(len(decision.todos), 1)

    def test_scope_gate_drops_scratch_path_dependency(self) -> None:
        state = _state([])
        llm_decision = PlannerDecision(
            summary="Continue from temporary output.",
            todos=[
                PlannedTodo(
                    goal="Parse /tmp/tcp_stream_7179.raw and recover the embedded artifact.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={"family": "forensics-extract"},
                    success_criteria=[
                        "Recover a complete candidate from the extracted artifact."
                    ],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertFalse(
            any(("decrypted_flag.png" in todo.goal for todo in decision.todos))
        )
        self.assertTrue(any(("scope gate dropped" in note for note in decision.notes)))

    def test_dependency_gate_drops_missing_planner_dependency(self) -> None:
        state = _state(["csawpad.py"])
        seed = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(seed, "done")
        llm_decision = PlannerDecision(
            summary="Plan dependent work.",
            todos=[
                PlannedTodo(
                    goal="Parse flag.stfu after the file discovery todo completes.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={"family": "crypto-model"},
                    depends_on=["recon-find-stfu-files"],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertFalse(
            any(("flag.stfu" in todo.goal for todo in decision.todos))
        )
        self.assertTrue(
            any(("dependency gate dropped" in note for note in decision.notes))
        )

    def test_dependency_gate_allows_existing_dependency_ref(self) -> None:
        state = _state(["csawpad.py"])
        upstream = todo_queue(state).enqueue(
            TodoItem(
                goal="Find encrypted challenge files.",
                phase=TodoPhase.RECON,
                dedupe_key="recon-find-stfu-files",
            )
        )
        todo_queue(state).complete(upstream, "no stfu files found")
        llm_decision = PlannerDecision(
            summary="Plan dependent work.",
            todos=[
                PlannedTodo(
                    goal="Analyze source after file discovery.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={"family": "crypto-model"},
                    depends_on=["recon-find-stfu-files"],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertEqual(len(decision.todos), 1)

    def test_dependency_gate_runs_after_progress_gate_drops_upstream_todo(
        self,
    ) -> None:
        state = _state(["cipher.bin"])
        queue = todo_queue(state)
        inventory = queue.enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        queue.complete(inventory, "done")
        for index in range(3):
            prior = queue.enqueue(
                TodoItem(
                    goal=f"Prior crypto model attempt {index}.",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "crypto-model"},
                    dedupe_key=f"prior-crypto-model-{index}",
                )
            )
            queue.partial(prior, "script (python)", "no flag candidate")
        llm_decision = PlannerDecision(
            summary="Plan a dependent decryption step.",
            todos=[
                PlannedTodo(
                    goal="Recover the key from known plaintext.",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "crypto-model"},
                    dedupe_key="known-plaintext-key-recovery",
                ),
                PlannedTodo(
                    goal="Decrypt files after key recovery.",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "flag-recovery"},
                    dedupe_key="decrypt-after-key",
                    depends_on=["known-plaintext-key-recovery"],
                ),
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertEqual(decision.todos, [])
        self.assertTrue(
            any(("progress gate dropped" in note for note in decision.notes))
        )
        self.assertTrue(
            any(("dependency gate dropped" in note for note in decision.notes))
        )

    def test_scope_gate_allows_registered_tmp_artifact(self) -> None:
        state = _state([])
        artifact = Artifact(
            path="/tmp/foremost_out/zip/00010174.zip",
            kind="foremost_zip",
            source="foremost",
        )
        state.artifacts[artifact.artifact_id] = artifact
        todo = PlannedTodo(
            goal="Inspect registered carved artifact /tmp/foremost_out/zip/00010174.zip.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context={
                "family": "artifact-followup",
                "path": "/tmp/foremost_out/zip/00010174.zip",
            },
            success_criteria=[
                "Extract grounded evidence from the registered artifact."
            ],
        )
        kept, notes = PlanningPipeline()._scope_gate([todo], state)
        self.assertEqual(kept, [todo])
        self.assertEqual(notes, [])

    def test_scope_gate_drops_unregistered_tmp_artifact(self) -> None:
        state = _state([])
        todo = PlannedTodo(
            goal="Inspect carved artifact /tmp/foremost_out/zip/00010174.zip.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context={
                "family": "artifact-followup",
                "path": "/tmp/foremost_out/zip/00010174.zip",
            },
            success_criteria=["Extract grounded evidence from the temporary artifact."],
        )
        kept, notes = PlanningPipeline()._scope_gate([todo], state)
        self.assertEqual(kept, [])
        self.assertTrue(any(("scope gate dropped" in note for note in notes)))

    def test_scope_gate_allows_in_step_temporary_workspace(self) -> None:
        state = _state([])
        llm_decision = PlannerDecision(
            summary="Use bounded local scratch space.",
            todos=[
                PlannedTodo(
                    goal="Build a bounded extraction script that creates its own temporary workspace.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={"family": "forensics-extract"},
                    success_criteria=[
                        "Recover a complete candidate from local challenge artifacts."
                    ],
                    constraints=["Do not depend on files written by earlier todos."],
                )
            ],
        )
        decision = PlanningPipeline().merge(state, llm_decision=llm_decision)
        self.assertEqual(len(decision.todos), 1)

    def test_scope_gate_drops_prior_generated_files_root_artifact(self) -> None:
        state = _state([], ["tcp://example:31337"])
        state.metadata["challenge"]["files"] = ["sleeping_dist.py"]
        todo = PlannedTodo(
            goal="Open the already-saved decrypted PNG at /home/ctfplayer/ctf_files/decrypted_flag.png and parse chunks.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context={
                "family": "flag-recovery",
                "files_root": "/home/ctfplayer/ctf_files",
                "known_facts": "evidence-deadbeef saved decrypted_flag.png in the previous script.",
            },
            success_criteria=["Extract a flag candidate from the PNG."],
        )
        kept, notes = PlanningPipeline()._scope_gate([todo], state)
        self.assertEqual(kept, [])
        self.assertTrue(any(("scope gate dropped" in note for note in notes)))

    def test_scope_gate_allows_durable_autopentest_artifact(self) -> None:
        state = _state([], ["tcp://example:31337"])
        state.metadata["challenge"]["files"] = ["sleeping_dist.py"]
        todo = PlannedTodo(
            goal="Open the generated artifact at /home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/decrypted.png and parse chunks.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context={
                "family": "artifact-followup",
                "files_root": "/home/ctfplayer/ctf_files",
                "path": "/home/ctfplayer/ctf_files/.autopentest_artifacts/script_1/scratch/decrypted.png",
            },
            success_criteria=["Extract grounded evidence from the durable artifact."],
        )
        kept, notes = PlanningPipeline()._scope_gate([todo], state)
        self.assertEqual(kept, [todo])
        self.assertEqual(notes, [])

    def test_scope_gate_allows_original_challenge_file_under_files_root(self) -> None:
        state = _state([], ["tcp://example:31337"])
        state.metadata["challenge"]["files"] = ["sleeping_dist.py"]
        todo = PlannedTodo(
            goal="Open the provided challenge file at /home/ctfplayer/ctf_files/sleeping_dist.py and inspect it.",
            phase=TodoPhase.ANALYSIS,
            priority=90,
            context={
                "family": "source-review",
                "files_root": "/home/ctfplayer/ctf_files",
            },
            success_criteria=["Recover algorithm facts from source."],
        )
        kept, notes = PlanningPipeline()._scope_gate([todo], state)
        self.assertEqual(kept, [todo])
        self.assertEqual(notes, [])

    def test_normalize_rewrites_files_root_artifact_path_to_durable_path(self) -> None:
        state = _state(["bundle.tar"], ["http://example.test"])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/shell_1/work/generated/app/config.txt",
            kind="shell_artifact_text",
            source="shell_exec",
            metadata={"relative_path": "generated/app/config.txt", "origin": "work"},
        )
        state.artifacts[artifact.artifact_id] = artifact
        todo = PlannedTodo(
            goal="Read /home/ctfplayer/ctf_files/generated/app/config.txt from the prior generated output.",
            phase=TodoPhase.ANALYSIS,
            priority=80,
            context={
                "family": "source-review",
                "files_root": "/home/ctfplayer/ctf_files",
                "path": "/home/ctfplayer/ctf_files/generated/app/config.txt",
            },
            success_criteria=["Inspect the generated config."],
        )
        normalized = normalize_todo(todo, state)
        self.assertEqual(normalized.context["path"], artifact.path)
        self.assertEqual(normalized.context["artifact_path"], artifact.path)
        self.assertIn(artifact.path, normalized.goal)
        self.assertEqual(normalized.context["family"], "artifact-followup")

    def test_normalize_adds_durable_artifact_paths_for_files_root_directory_prefix(
        self,
    ) -> None:
        state = _state(["bundle.tar"], ["http://example.test"])
        first = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/shell_1/work/generated/app/views/login.txt",
            kind="shell_artifact_text",
            source="shell_exec",
            metadata={
                "relative_path": "generated/app/views/login.txt",
                "origin": "work",
            },
        )
        second = Artifact(
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/shell_1/work/generated/app/views/profile.txt",
            kind="shell_artifact_text",
            source="shell_exec",
            metadata={
                "relative_path": "generated/app/views/profile.txt",
                "origin": "work",
            },
        )
        state.artifacts[first.artifact_id] = first
        state.artifacts[second.artifact_id] = second
        todo = PlannedTodo(
            goal="Read generated application views from the extracted workspace.",
            phase=TodoPhase.ANALYSIS,
            priority=80,
            context={
                "family": "source-review",
                "files_root": "/home/ctfplayer/ctf_files",
                "extracted_root": "/home/ctfplayer/ctf_files/generated/app",
                "candidate_paths": ["views/login.txt", "views/profile.txt"],
            },
            constraints=["Read only from /home/ctfplayer/ctf_files/generated/app."],
            success_criteria=["Inspect the generated views."],
        )
        normalized = normalize_todo(todo, state)
        self.assertEqual(
            normalized.context["durable_artifact_paths"], [first.path, second.path]
        )
        self.assertEqual(normalized.context["paths"], [first.path, second.path])
        self.assertIn(".autopentest_artifacts", normalized.context["extracted_root"])
        self.assertIn(".autopentest_artifacts", normalized.constraints[0])

    def test_forensics_planning_profile_is_prompt_safe(self) -> None:
        matrix = technique_matrix_for("forensics")
        forensics = next(
            (item for item in matrix if item["family"] == "forensics-extract")
        )
        self.assertEqual(forensics["phase"], "analysis")
        self.assertIn("pcap streams", forensics["evidence_facets"])
        self.assertNotIn("objective", forensics)
        self.assertNotIn("failure_escape", forensics)

    def test_protocol_near_miss_does_not_seed_crypto_refinement(self) -> None:
        state = _state([])
        state.metadata["challenge"]["category"] = "misc"
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Build a bounded TCP protocol solver and parse service prompts.",
                phase=TodoPhase.EXPLOIT,
                context={"family": "network-protocol"},
                dedupe_key="protocol-solver",
            )
        )
        todo_queue(state).start(todo, "exploit-worker")
        todo_queue(state).partial(
            todo, "Service interaction captured prompts.", "no flag candidate"
        )
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id=todo.todo_id,
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="script (python) - readable near-miss output",
                extracted={
                    "output_context": {
                        "near_miss_candidates": [
                            "readable/plaintext-or-ascii-art preview:\namount prompt accepted"
                        ],
                        "stdout": "connected to raw tcp service\nround 1 amount prompt\nhex dump: 616d6f756e74\n",
                        "result_quality": "partial_no_candidate",
                    }
                },
            )
        )
        decision = PlanningPipeline().plan(state)
        self.assertFalse(
            any(
                (
                    todo.context.get("family") == "crypto-decrypt"
                    for todo in decision.todos
                )
            )
        )

    def test_decode_near_miss_seeds_crypto_refinement(self) -> None:
        state = _state([])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Decrypt the ciphertext and recover the plaintext flag.",
                phase=TodoPhase.ANALYSIS,
                context={"family": "crypto-decrypt"},
                dedupe_key="decrypt-attempt",
            )
        )
        todo_queue(state).start(todo, "artifact-worker")
        todo_queue(state).partial(
            todo, "Decoder produced garbled plaintext.", "encoding mismatch"
        )
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id=todo.todo_id,
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="script produced near-miss decrypted plaintext",
                extracted={
                    "output_context": {
                        "near_miss_candidates": ["flag{almost_readable}"],
                        "stdout": "garbled plaintext from xor decode",
                        "result_quality": "partial_no_candidate",
                    }
                },
            )
        )
        decision = PlanningPipeline().plan(state)
        self.assertTrue(
            any(
                (
                    todo.context.get("family") == "crypto-decrypt"
                    for todo in decision.todos
                )
            )
        )


class TodoNormalizationTests(unittest.TestCase):
    def test_file_goal_gets_canonical_files_context(self) -> None:
        state = _state(["solve.py"])
        todo = PlannedTodo(
            goal="Review source files for crypto weakness.", phase=TodoPhase.ANALYSIS
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["files_root"], "/home/ctfplayer/ctf_files")
        self.assertEqual(todo.context["challenge_files"], ["solve.py"])
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_flag_recovery_file_analysis_stays_analysis(self) -> None:
        state = _state(["cipher.mpeg"])
        todo = PlannedTodo(
            goal="Perform deep analysis of the MPEG file to identify the cipher and recover the flag.",
            phase=TodoPhase.FLAG_VALIDATION,
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["files_root"], "/home/ctfplayer/ctf_files")
        self.assertEqual(todo.context["challenge_files"], ["cipher.mpeg"])
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_ungrounded_candidate_flag_context_stays_analysis(self) -> None:
        todo = PlannedTodo(
            goal="Validate recovered candidate.",
            phase=TodoPhase.FLAG_VALIDATION,
            context={"candidate_flag": "flag{okay}"},
        )
        normalize_todo(todo, _state([]))
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_state_candidate_flag_context_promotes_validation(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        todo = PlannedTodo(
            goal="Validate recovered candidate.",
            context={"candidate_flag": "flag{okay}"},
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.FLAG_VALIDATION)

    def test_ungrounded_flag_validation_decryption_todo_becomes_analysis(self) -> None:
        state = _state(["stfu", "flag.stfu"])
        todo = PlannedTodo(
            goal="Write and execute a Python script that implements the LFSR-based decryption: read flag.stfu, reproduce the keystream, and print the recovered plaintext.",
            phase=TodoPhase.FLAG_VALIDATION,
            context={
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": ["stfu", "flag.stfu"],
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_local_artifact_recovery_exploit_todo_becomes_analysis(self) -> None:
        state = _state(["cipher.bin", "cipher.c"])
        todo = PlannedTodo(
            goal="Write a minimal C decryption program that ports the source cipher and recovers plaintext.",
            phase=TodoPhase.EXPLOIT,
            context={
                "files_root": "/home/ctfplayer/ctf_files",
                "data_file": "/home/ctfplayer/ctf_files/cipher.bin",
                "family": "flag-recovery",
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )

    def test_remote_exploit_todo_stays_exploit(self) -> None:
        state = _state(["server.py"])
        todo = PlannedTodo(
            goal="Exploit the remote HTTP service with the recovered token.",
            phase=TodoPhase.EXPLOIT,
            context={"base_url": "http://target:8080", "family": "flag-recovery"},
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.EXPLOIT)

    def test_recovery_todo_gets_execution_closure_context(self) -> None:
        state = _state(["cipher.bin", "decoder.c"])
        todo = PlannedTodo(
            goal="Port the source cipher and recover the plaintext flag.",
            phase=TodoPhase.ANALYSIS,
            context={},
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "crypto-decrypt")
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "script.exec"
        )
        self.assertNotIn("completion_contract", todo.context["dispatch_intent"])
        self.assertNotIn("repair_policy_id", todo.context["dispatch_intent"])

    def test_crypto_source_understanding_todo_does_not_require_candidate_closure(
        self,
    ) -> None:
        state = _state(["bundle"])
        todo = PlannedTodo(
            goal="Examine the source crypto helper implementation to understand the cipher algorithm, key management, and encryption/decryption flow.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "crypto-decrypt",
                "source_files": ["/home/ctfplayer/ctf_files/helper"],
            },
            success_criteria=[
                "Document the algorithm and key handling evidence needed for a later step."
            ],
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "crypto-decrypt")
        self.assertNotIn("execution_closure", todo.context)
        self.assertNotEqual(
            todo.context["dispatch_intent"].get("profile"), "execution_closure"
        )
        self.assertNotEqual(
            todo.context["dispatch_intent"].get("required_capability"), "script.exec"
        )

    def test_archive_extraction_todo_uses_executable_extraction_capability(
        self,
    ) -> None:
        state = _state(["bundle.random"])
        todo = PlannedTodo(
            goal="Extract bundle.random to a working directory and list the full source tree.",
            phase=TodoPhase.ANALYSIS,
            context={
                "dispatch_intent": {
                    "profile": "artifact_analysis",
                    "required_capability": "artifact.triage",
                }
            },
        )
        normalize_todo(todo, state)
        self.assertNotIn("archive_extraction", todo.context)
        self.assertEqual(_capability(todo), "shell.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "shell.exec"
        )

    def test_exploit_todo_with_stale_artifact_triage_hint_gets_execution_closure(
        self,
    ) -> None:
        state = _state(["target.bin"], ["tcp://service.example:31337"])
        todo = PlannedTodo(
            goal="Execute the full exploit chain against the authorized service: authenticate, send the crafted payload, and recover the flag.",
            phase=TodoPhase.EXPLOIT,
            context={
                "family": "exploit-execution",
                "dispatch_intent": {
                    "profile": "artifact_analysis",
                    "required_capability": "artifact.triage",
                },
                "path": "/home/ctfplayer/ctf_files/target.bin",
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(_capability(todo), "script.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "script.exec"
        )

    def test_exploit_todo_sets_active_exploit_profile(self) -> None:
        state = _state(["target.bin"], ["tcp://service.example:31337"])
        todo = PlannedTodo(
            goal="Construct and execute an exploit against the authorized service, send the crafted payload, and capture a flag candidate.",
            phase=TodoPhase.EXPLOIT,
            context={
                "family": "pwn-exploit",
                "scope": "tcp://service.example:31337",
                "files_root": "/home/ctfplayer/ctf_files",
                "dispatch_intent": {
                    "profile": "pwn_exploit",
                    "target_refs": {
                        "scope": "tcp://service.example:31337",
                        "files_root": "/home/ctfplayer/ctf_files",
                    },
                },
            },
            success_criteria=["Exploit returns output containing a flag candidate."],
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "pwn-exploit")
        self.assertEqual(_capability(todo), "script.exec")
        self.assertEqual(todo.context["dispatch_intent"]["profile"], "pwn_exploit")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "script.exec"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["target_refs"]["scope"],
            "tcp://service.example:31337",
        )

    def test_algorithm_verification_gets_execution_closure_context(self) -> None:
        state = _state(["cipher.py", "capture.bin"])
        todo = PlannedTodo(
            goal="Apply the reference algorithm to local bytes and recover a candidate.",
            phase=TodoPhase.ANALYSIS,
            context={"family": "algorithm-verification"},
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "algorithm-verification")
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )

    def test_binary_static_closure_overrides_stale_artifact_triage_hint(self) -> None:
        state = _state(["program"])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/program",
            kind="binary",
            source="artifact_triage",
            size=4096,
        )
        state.artifacts[artifact.artifact_id] = artifact
        todo = PlannedTodo(
            goal="Reverse engineer the binary authentication transform and derive the password candidate.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "binary-static",
                "artifact_path": artifact.path,
                "path": artifact.path,
                "dispatch_intent": {
                    "profile": "binary_static",
                    "required_capability": "artifact.triage",
                },
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "binary-static")
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )
        self.assertEqual(_capability(todo), "script.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "script.exec"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_closure"
        )

    def test_binary_static_deep_analysis_overrides_stale_artifact_triage_hint(
        self,
    ) -> None:
        state = _state(["program"])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/program",
            kind="binary",
            source="artifact_triage",
            size=4096,
        )
        state.artifacts[artifact.artifact_id] = artifact
        todo = PlannedTodo(
            goal="Run comprehensive static analysis on the binary: check mitigations, disassemble entry functions, locate useful gadgets, and confirm control-flow evidence.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "binary-static",
                "artifact_path": artifact.path,
                "path": artifact.path,
                "dispatch_intent": {
                    "profile": "binary_static",
                    "required_capability": "artifact.triage",
                },
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "binary-static")
        self.assertEqual(_capability(todo), "shell.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "shell.exec"
        )
        self.assertEqual(todo.context["dispatch_intent"]["profile"], "binary_analysis")

    def test_binary_dynamic_analysis_preserves_canonical_binary_profile(self) -> None:
        state = _state(["program"])
        artifact = Artifact(
            path="/home/ctfplayer/ctf_files/program",
            kind="binary",
            source="artifact_triage",
            size=4096,
        )
        state.artifacts[artifact.artifact_id] = artifact
        todo = PlannedTodo(
            goal="Analyze the local binary with GDB and disassembly to trace the exact execution path for the crashing input.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "binary-dynamic",
                "artifact_path": artifact.path,
                "path": artifact.path,
                "scope": "tcp://target.example:31337",
                "dispatch_intent": {
                    "profile": "binary_analysis",
                    "required_capability": "shell.exec",
                },
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.context["family"], "binary-dynamic")
        self.assertEqual(_capability(todo), "shell.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "shell.exec"
        )
        self.assertEqual(todo.context["dispatch_intent"]["profile"], "binary_analysis")

    def test_raw_content_goal_overrides_stale_artifact_triage_hint(self) -> None:
        state = _state(["source.txt"])
        todo = PlannedTodo(
            goal="Read the complete raw file content and search every line for candidate secrets that a first-pass artifact summary may have truncated.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "artifact-inventory",
                "path": "/home/ctfplayer/ctf_files/source.txt",
                "dispatch_intent": {
                    "profile": "artifact_analysis",
                    "required_capability": "artifact.triage",
                },
            },
        )
        normalize_todo(todo, state)
        self.assertEqual(_capability(todo), "shell.exec")
        self.assertEqual(
            todo.context["dispatch_intent"]["required_capability"], "shell.exec"
        )
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "artifact_analysis"
        )

    def test_crypto_model_todo_preserves_structured_dispatch_intent(self) -> None:
        state = _state(["cipher.py", "capture.bin"])
        todo = PlannedTodo(
            goal="XOR-decrypt the recovered ciphertext bytes and extract the flag.",
            phase=TodoPhase.ANALYSIS,
            context={
                "family": "crypto-model",
                "dispatch_intent": {
                    "profile": "crypto_model",
                    "required_capability": None,
                    "evidence_ids": ["evidence-old"],
                },
            },
        )
        normalize_todo(todo, state)
        self.assertNotIn("execution_closure", todo.context)
        self.assertNotIn("capability_hint", todo.context)
        self.assertNotIn("required_capability", todo.context["dispatch_intent"])
        self.assertEqual(
            todo.context["dispatch_intent"]["evidence_ids"], ["evidence-old"]
        )

    def test_execution_continuation_todo_stays_open_dispatch(self) -> None:
        state = _state(["solve.py"])
        todo = PlannedTodo(
            goal="Continue from the latest grounded evidence and execute the next bounded step toward recovering a flag candidate.",
            phase=TodoPhase.ANALYSIS,
            context={"family": "execution-continuation"},
        )
        normalize_todo(todo, state)
        self.assertNotIn("execution_closure", todo.context)
        self.assertEqual(
            todo.context["dispatch_intent"]["profile"], "execution_continuation"
        )
        self.assertNotIn("required_capability", todo.context["dispatch_intent"])

    def test_flag_format_template_is_not_a_concrete_candidate(self) -> None:
        state = _state(["stfu", "flag.stfu"])
        todo = PlannedTodo(
            goal="Implement the LFSR decryption and print the recovered plaintext in the expected flag{...} format.",
            phase=TodoPhase.FLAG_VALIDATION,
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertNotIn("candidate_flag", todo.context)

    def test_state_flag_candidate_keeps_explicit_validation_phase(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        todo = PlannedTodo(
            goal="Validate the recovered candidate flag.",
            phase=TodoPhase.FLAG_VALIDATION,
        )
        normalize_todo(todo, state)
        self.assertEqual(todo.phase, TodoPhase.FLAG_VALIDATION)

    def test_family_for_recognizes_list_files_as_artifact_inventory(self) -> None:
        family = family_for(
            "List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts."
        )
        self.assertEqual(family, "artifact-inventory")

    def test_family_for_overrides_explicit_other(self) -> None:
        family = family_for(
            "List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts.",
            context={"family": "other"},
        )
        self.assertEqual(family, "artifact-inventory")


class PlanningPipelineDedupTests(unittest.TestCase):
    def test_drops_duplicate_dedupe_keys(self) -> None:
        state = _state([])
        todos = [
            PlannedTodo(goal="A", dedupe_key="same"),
            PlannedTodo(goal="B", dedupe_key="same"),
        ]
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="dedupe", todos=todos)
        )
        self.assertEqual([todo.goal for todo in decision.todos], ["A"])

    def test_collapses_two_artifact_inventory_todos_with_different_keys(self) -> None:
        state = _state(["stfu", "flag.stfu"])
        llm_todo = PlannedTodo(
            goal="List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts.",
            phase=TodoPhase.RECON,
            context={
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": ["stfu", "flag.stfu"],
            },
        )
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="dup", todos=[llm_todo])
        )
        inventory_todos = [
            todo
            for todo in decision.todos
            if todo.context.get("family") == "artifact-inventory"
        ]
        self.assertEqual(len(inventory_todos), 1)
        self.assertTrue(any(("dropped" in note for note in decision.notes)))

    def test_collapses_duplicate_flag_validation_for_same_candidate(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="script")
        state.flag_candidates[candidate.candidate_id] = candidate
        llm_todo = PlannedTodo(
            goal="Validate candidate flag{okay}.",
            phase=TodoPhase.FLAG_VALIDATION,
            context={"candidate_flag": "flag{okay}"},
            dedupe_key="llm-validation",
        )
        decision = PlanningPipeline().merge(
            state, llm_decision=PlannerDecision(summary="validate", todos=[llm_todo])
        )
        validation_todos = [
            todo for todo in decision.todos if todo.phase == TodoPhase.FLAG_VALIDATION
        ]
        self.assertEqual(len(validation_todos), 1)
        self.assertEqual(validation_todos[0].context["candidate_flag"], "flag{okay}")
        self.assertTrue(any(("dropped" in note for note in decision.notes)))

    def test_partial_todo_blocks_same_dedupe_key_but_allows_new_key(self) -> None:
        state = _state([])
        partial = todo_queue(state).enqueue(
            TodoItem(
                goal="Try LFSR decrypt.",
                phase=TodoPhase.ANALYSIS,
                context={"family": "crypto-decrypt"},
                dedupe_key="decrypt-same",
            )
        )
        todo_queue(state).start(partial, "artifact-worker")
        todo_queue(state).partial(
            partial, "script completed without a flag", "no candidate"
        )
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="retry",
                todos=[
                    PlannedTodo(
                        goal="Retry the same LFSR decrypt.",
                        phase=TodoPhase.ANALYSIS,
                        context={"family": "crypto-decrypt"},
                        dedupe_key="decrypt-same",
                    ),
                    PlannedTodo(
                        goal="Retry LFSR decrypt using newly extracted tap evidence.",
                        phase=TodoPhase.ANALYSIS,
                        context={
                            "family": "crypto-decrypt",
                            "novelty_key": "tap-evidence-1",
                        },
                        dedupe_key="decrypt-with-tap-evidence",
                    ),
                ],
            ),
        )
        self.assertEqual(
            [todo.dedupe_key for todo in decision.todos], ["decrypt-with-tap-evidence"]
        )
        self.assertTrue(any(("dropped 1 duplicate" in note for note in decision.notes)))


class LLMPlannerTests(unittest.TestCase):
    def test_planner_summary_sanitizes_source_identity_terms(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "The RAG retrieval result is a self-hit. The knowledge hints confirm the related writeup for the 'stfu' challenge is highly similar (score 0.879) and source identity labels describe an LFSR cipher from the exact same CSAW challenge in oracle mode.",
                        "todos": [
                            {
                                "goal": "Use the RAG retrieval result from oracle mode to port the solver.",
                                "phase": "recon",
                                "context": {"family": "solver-port"},
                                "success_criteria": [
                                    "Do not rely on the self-hit label."
                                ],
                                "constraints": [
                                    "Treat oracle source identity labels as provenance only."
                                ],
                                "dedupe_key": "solver-port",
                            },
                            {
                                "goal": "Assess whether the service exposes a padding oracle.",
                                "phase": "recon",
                                "context": {"family": "padding-oracle-assessment"},
                                "dedupe_key": "padding-oracle-assessment",
                            },
                        ],
                        "notes": [
                            "RAG retrieval hits and oracle source identity labels were used for planning."
                        ],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(_state([]))
        note_text = "\n".join(decision.notes).lower()
        todo_text = "\n".join(
            (
                text
                for todo in decision.todos
                for text in [todo.goal, *todo.success_criteria, *todo.constraints]
            )
        ).lower()
        self.assertIn("closely related challenge", decision.summary)
        self.assertIn("technical context", decision.summary)
        self.assertIn("technical evidence suggests", decision.summary.lower())
        self.assertNotIn("technical context confirm", decision.summary.lower())
        self.assertNotIn("exact same", decision.summary.lower())
        self.assertNotIn("oracle", decision.summary.lower())
        self.assertNotIn("rag", decision.summary.lower())
        self.assertNotIn("retrieval", decision.summary.lower())
        self.assertNotIn("self-hit", decision.summary.lower())
        self.assertNotIn("writeup", decision.summary.lower())
        self.assertNotIn("source identity", decision.summary.lower())
        self.assertNotIn("score", decision.summary.lower())
        self.assertNotIn("knowledge hints", decision.summary.lower())
        self.assertNotIn("rag", note_text)
        self.assertNotIn("retrieval", note_text)
        self.assertNotIn("oracle", note_text)
        self.assertNotIn("source identity", note_text)
        self.assertIn("port the solver", todo_text)
        self.assertIn("padding oracle", todo_text)
        self.assertNotIn("rag", todo_text)
        self.assertNotIn("retrieval", todo_text)
        self.assertNotIn("oracle mode", todo_text)
        self.assertNotIn("self-hit", todo_text)
        self.assertNotIn("source identity", todo_text)

    def test_planner_combines_bootstrap_and_llm_todos(self) -> None:
        state = _state(["solve.py"])
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "review source",
                        "todos": [
                            {
                                "goal": "Review the bundled solve.py source for crypto weakness.",
                                "phase": "recon",
                                "priority": "high",
                                "context": {"seed_terms": ["solve.py"]},
                                "success_criteria": ["Read solve.py end to end."],
                                "constraints": ["Use local files only."],
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.summary, "review source")
        self.assertGreaterEqual(len(decision.todos), 2)
        self.assertEqual({todo.phase for todo in decision.todos}, {TodoPhase.RECON})
        llm_todo = next((todo for todo in decision.todos if "solve.py" in todo.goal))
        self.assertEqual(llm_todo.priority, 75)
        self.assertEqual(llm_todo.context["files_root"], "/home/ctfplayer/ctf_files")

    def test_planner_keeps_only_frontier_phase_from_mixed_llm_batch(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "mixed batch",
                        "todos": [
                            {
                                "goal": "Map authorized scope.",
                                "phase": "recon",
                                "priority": 90,
                                "context": {"scope": "http://example.test"},
                            },
                            {
                                "goal": "Exploit the discovered issue.",
                                "phase": "exploit",
                                "priority": 80,
                                "context": {"base_url": "http://example.test"},
                            },
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(_state([]))
        self.assertEqual([todo.phase for todo in decision.todos], [TodoPhase.RECON])
        self.assertTrue(any(("phase gate" in note for note in decision.notes)))

    def test_planner_continues_open_phase_before_downstream_phase(self) -> None:
        state = _state([])
        todo_queue(state).enqueue(
            TodoItem(
                goal="Review source for vulnerability.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="open-analysis",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "premature exploit",
                        "todos": [
                            {
                                "goal": "Exploit reviewed vulnerability.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"vulnerability_id": "vuln-1"},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("dropped 1" in note for note in decision.notes)))

    def test_planner_drops_ungrounded_exploit_todo(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "ungrounded exploit",
                        "todos": [
                            {
                                "goal": "Exploit an assumed vulnerability.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"base_url": "http://example.test"},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(_state([]))
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("ungrounded exploit" in note for note in decision.notes)))

    def test_planner_drops_exploit_with_only_global_evidence(self) -> None:
        state = _state([])
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-inventory",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Inventory completed.",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "premature exploit",
                        "todos": [
                            {
                                "goal": "Exploit an assumed issue from prior output.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    },
                    {
                        "summary": "exhausted",
                        "todos": [],
                        "notes": [],
                        "stop_run": True,
                    },
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("ungrounded exploit" in note for note in decision.notes)))

    def test_planner_allows_exploit_with_explicit_evidence_id(self) -> None:
        state = _state([])
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-analysis",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Evidence shows controllable return address.",
            )
        )
        evidence_id = next(iter(state.evidence))
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "grounded exploit",
                        "todos": [
                            {
                                "goal": "Exploit the controllable return address.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"evidence_ids": [evidence_id]},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_allows_exploit_with_existing_endpoint_id(self) -> None:
        state = _state([])
        endpoint = Endpoint(hostname="example.test", port=8000, protocol="tcp")
        StateDeltaApplier(state).apply(StateDelta(endpoints=[endpoint]))
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "endpoint-driven exploit",
                        "todos": [
                            {
                                "goal": "Run the solver against the observed TCP service.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"endpoint_id": endpoint.endpoint_id},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_allows_exploit_with_observed_endpoint_url(self) -> None:
        state = _state([])
        StateDeltaApplier(state).apply(
            StateDelta(
                endpoints=[
                    Endpoint(
                        hostname="example.test",
                        port=8000,
                        protocol="tcp",
                        metadata={"service": "raw-tcp"},
                    )
                ]
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "observed service exploit",
                        "todos": [
                            {
                                "goal": "Run the verified solver against the observed service.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"base_url": "http://example.test:8000"},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_drops_exploit_with_unobserved_endpoint_url(self) -> None:
        state = _state([])
        StateDeltaApplier(state).apply(
            StateDelta(
                endpoints=[
                    Endpoint(
                        url="http://example.test:8000",
                        hostname="example.test",
                        port=8000,
                        protocol="http",
                    )
                ]
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "unobserved service exploit",
                        "todos": [
                            {
                                "goal": "Run the solver against a URL that has not returned service evidence.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"base_url": "http://example.test:8000"},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("ungrounded exploit" in note for note in decision.notes)))

    def test_planner_drops_exploit_with_unknown_evidence_id(self) -> None:
        state = _state([])
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-analysis",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Evidence exists, but this is not the referenced record.",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "ungrounded exploit",
                        "todos": [
                            {
                                "goal": "Exploit output that is not in state.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"evidence_ids": ["missing-evidence"]},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    },
                    {
                        "summary": "exhausted",
                        "todos": [],
                        "notes": [],
                        "stop_run": True,
                    },
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("ungrounded exploit" in note for note in decision.notes)))

    def test_planner_allows_exploit_with_existing_hypothesis_id(self) -> None:
        state = _state([])
        hypothesis = Hypothesis(title="Stack offset can overwrite the return address.")
        StateDeltaApplier(state).apply(StateDelta(hypotheses=[hypothesis]))
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "hypothesis-driven exploit",
                        "todos": [
                            {
                                "goal": "Test exploit payload for the return-address hypothesis.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"hypothesis_id": hypothesis.hypothesis_id},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_drops_exploit_with_unreferenced_finding(self) -> None:
        state = _state([])
        ReconFactStore(state).finding(
            Finding(finding_id="finding-1", title="SQLi", severity=Severity.HIGH)
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "missing finding ref",
                        "todos": [
                            {
                                "goal": "Exploit the discovered finding.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(decision.todos, [])
        self.assertTrue(any(("ungrounded exploit" in note for note in decision.notes)))

    def test_planner_allows_exploit_with_existing_finding_id(self) -> None:
        state = _state([])
        ReconFactStore(state).finding(
            Finding(finding_id="finding-1", title="SQLi", severity=Severity.HIGH)
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "finding-driven exploit",
                        "todos": [
                            {
                                "goal": "Exploit the SQL injection finding.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {"finding_id": "finding-1"},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_allows_exploit_with_typed_vulnerability_state(self) -> None:
        state = _state([])
        StateDeltaApplier(state).apply(
            StateDelta(
                vulnerabilities=[Vulnerability(title="Controllable return address.")]
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "vulnerability-driven exploit",
                        "todos": [
                            {
                                "goal": "Exploit the controllable return address.",
                                "phase": "exploit",
                                "priority": 90,
                                "context": {},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_respects_stop_run(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient(
                [{"summary": "done", "todos": [], "notes": [], "stop_run": True}]
            )
        )
        self.assertTrue(planner.plan(_state([])).stop_run)

    def test_planner_retries_empty_non_terminal_decision(self) -> None:
        captured: list[dict[str, object]] = []

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured.append(json.loads(user_prompt))
            if len(captured) == 1:
                return {
                    "summary": "observed but no action",
                    "todos": [],
                    "notes": [],
                    "stop_run": False,
                }
            return {
                "summary": "continue from evidence",
                "todos": [
                    {
                        "goal": "Analyze the latest service evidence and derive the next executable exploit step.",
                        "phase": "analysis",
                        "priority": 85,
                        "context": {"evidence_id": "evidence-service"},
                        "success_criteria": [
                            "Produce a concrete executable next step."
                        ],
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state([])
        prior = todo_queue(state).enqueue(
            TodoItem(goal="Probe service.", phase=TodoPhase.RECON, dedupe_key="probe")
        )
        todo_queue(state).complete(prior, "service banner captured")
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                evidence_id="evidence-service",
                task_id=prior.todo_id,
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="raw TCP service banner captured",
                extracted={"output_context": {"stdout": "ready for commands"}},
            )
        )
        decision = LLMPlanner(
            StaticLLMClient(responder), augmenter=RagAugmenter(None)
        ).plan(state)
        self.assertEqual(len(captured), 2)
        self.assertNotIn("planner_retry_instruction", captured[0])
        self.assertIn("planner_retry_instruction", captured[1])
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)
        self.assertTrue(any(("retried after empty" in note for note in decision.notes)))

    def test_planner_retries_when_only_proposed_todo_is_deduped(self) -> None:
        captured: list[dict[str, object]] = []

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured.append(json.loads(user_prompt))
            if len(captured) == 1:
                return {
                    "summary": "repeat inventory",
                    "todos": [
                        {
                            "goal": "Inventory and classify bundled challenge files.",
                            "phase": "recon",
                            "priority": 95,
                            "context": {"family": "artifact-inventory"},
                            "success_criteria": ["Classify files."],
                            "dedupe_key": "bootstrap:artifact-inventory",
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            return {
                "summary": "execute from technical context",
                "todos": [
                    {
                        "goal": "Build a bounded solver harness from the latest technical context and local artifacts.",
                        "phase": "analysis",
                        "priority": 90,
                        "context": {
                            "family": "algorithm-verification",
                            "dispatch_intent": {
                                "profile": "execution_closure",
                                "required_capability": "script.exec",
                            },
                        },
                        "success_criteria": [
                            "Return recovered candidates through normal tool output."
                        ],
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state(["capture.bin"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "done")
        decision = LLMPlanner(
            StaticLLMClient(responder), augmenter=RagAugmenter(None)
        ).plan(state)
        self.assertEqual(len(captured), 2)
        self.assertNotIn("planner_retry_instruction", captured[0])
        self.assertIn("planner_retry_instruction", captured[1])
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)
        self.assertTrue(any(("retried after empty" in note for note in decision.notes)))

    def test_planner_retries_when_gate_drops_all_llm_todos(self) -> None:
        captured: list[dict[str, object]] = []

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured.append(json.loads(user_prompt))
            if len(captured) == 1:
                return {
                    "summary": "bad local pivot",
                    "todos": [
                        {
                            "goal": "Connect to localhost:9999 and inspect the service.",
                            "phase": "analysis",
                            "priority": 80,
                            "context": {"scope": "http://127.0.0.1:9999"},
                            "success_criteria": ["Capture a banner."],
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            return {
                "summary": "use local artifacts",
                "todos": [
                    {
                        "goal": "Analyze bundled files and produce a bounded diagnostic.",
                        "phase": "analysis",
                        "priority": 80,
                        "context": {
                            "files_root": "/home/ctfplayer/ctf_files",
                            "challenge_files": ["capture.bin"],
                        },
                        "success_criteria": ["Use only bundled artifacts."],
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state(["capture.bin"], ["tcp://remote.example:9000"])
        prior = todo_queue(state).enqueue(
            TodoItem(
                goal="Map authorized scope entry 1.",
                phase=TodoPhase.RECON,
                context={"scope": "tcp://remote.example:9000", "family": "recon"},
                dedupe_key="bootstrap:scope:tcp://remote.example:9000",
            )
        )
        todo_queue(state).complete(
            prior, "remote service unavailable; use bundled files"
        )
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "capture.bin")
        decision = LLMPlanner(
            StaticLLMClient(responder), augmenter=RagAugmenter(None)
        ).plan(state)
        self.assertEqual(len(captured), 2)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)
        self.assertTrue(any(("retried after empty" in note for note in decision.notes)))

    def test_planner_retries_when_dependency_gate_drops_all_llm_todos(self) -> None:
        captured: list[dict[str, object]] = []

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured.append(json.loads(user_prompt))
            if len(captured) == 1:
                return {
                    "summary": "dependent missing artifact step",
                    "todos": [
                        {
                            "goal": "Parse flag.stfu after file discovery completes.",
                            "phase": "analysis",
                            "priority": 90,
                            "context": {"family": "crypto-model"},
                            "depends_on": ["recon-find-stfu-files"],
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            return {
                "summary": "continue with local source",
                "todos": [
                    {
                        "goal": "Analyze the available source file and identify embedded ciphertext.",
                        "phase": "analysis",
                        "priority": 80,
                        "context": {
                            "family": "crypto-model",
                            "files_root": "/home/ctfplayer/ctf_files",
                            "challenge_files": ["csawpad.py"],
                        },
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state(["csawpad.py"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                context={"family": "artifact-inventory"},
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "only csawpad.py is present")
        decision = LLMPlanner(
            StaticLLMClient(responder), augmenter=RagAugmenter(None)
        ).plan(state)
        self.assertEqual(len(captured), 2)
        self.assertIn("planner_retry_instruction", captured[1])
        self.assertEqual(len(decision.todos), 1)
        self.assertFalse(any(("flag.stfu" in todo.goal for todo in decision.todos)))
        self.assertTrue(any(("retried after empty" in note for note in decision.notes)))

    def test_planner_synthesizes_grounded_continuation_after_repeated_empty_plans(
        self,
    ) -> None:
        state = _state([])
        prior = todo_queue(state).enqueue(
            TodoItem(
                goal="Probe raw TCP service.", phase=TodoPhase.RECON, dedupe_key="probe"
            )
        )
        todo_queue(state).complete(prior, "captured first prompt")
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                evidence_id="evidence-service",
                task_id=prior.todo_id,
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="connected and captured first protocol prompt",
                extracted={"output_context": {"stdout": "amount prompt captured"}},
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "observed but no action",
                        "todos": [],
                        "notes": [],
                        "stop_run": False,
                    },
                    {
                        "summary": "still no action",
                        "todos": [],
                        "notes": [],
                        "stop_run": False,
                    },
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        todo = decision.todos[0]
        self.assertEqual(todo.phase, TodoPhase.EXPLOIT)
        self.assertEqual(todo.context["family"], "execution-continuation")
        self.assertEqual(todo.context["evidence_ids"], ["evidence-service"])
        self.assertTrue(
            any(("repeated empty plans" in note for note in decision.notes))
        )

    def test_planner_keeps_no_progress_local_continuation_in_analysis(self) -> None:
        state = _state(["cipher.bin"])
        inventory = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(inventory, "cipher.bin")
        closure = todo_queue(state).enqueue(
            TodoItem(
                goal="Build and run a bounded solver harness from current evidence.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="bootstrap:evidence-execution-closure",
            )
        )
        todo_queue(state).complete(closure, "bounded harness produced no candidate")
        prior = todo_queue(state).enqueue(
            TodoItem(
                goal="Try local solver variant.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="local-solver",
            )
        )
        todo_queue(state).start(prior, "artifact-worker")
        todo_queue(state).partial(
            prior,
            "script (python)",
            "script exited successfully but no flag candidate was recovered",
        )
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                evidence_id="evidence-no-candidate",
                task_id=prior.todo_id,
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="script ran without recovering a candidate",
                extracted={
                    "output_context": {
                        "result_quality": "partial_no_candidate",
                        "failure_kind": "no_candidate",
                        "flag_candidates": [],
                    }
                },
            )
        )
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "observed but no action",
                        "todos": [],
                        "notes": [],
                        "stop_run": False,
                    },
                    {
                        "summary": "still no action",
                        "todos": [],
                        "notes": [],
                        "stop_run": False,
                    },
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        todo = decision.todos[0]
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertEqual(todo.context["family"], "execution-continuation")
        self.assertNotIn("evidence_ids", todo.context)

    def test_planner_raises_when_llm_fails(self) -> None:
        planner = LLMPlanner(StaticLLMClient([]))
        with self.assertRaises(LLMClientError):
            planner.plan(_state(["solve.py"]))

    def test_planner_keeps_mislabelled_flag_recovery_analysis_todo(self) -> None:
        state = _state(["cipher.mpeg"])
        bootstrap = todo_queue(state).enqueue(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        todo_queue(state).complete(bootstrap, "one MPEG-like text artifact found")
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "analyze MPEG",
                        "todos": [
                            {
                                "goal": "Perform deep analysis of the MPEG file to identify the cipher and recover the flag.",
                                "phase": "flag_validation",
                                "priority": 90,
                                "context": {"challenge_files": ["cipher.mpeg"]},
                                "success_criteria": [
                                    "Produce a decrypted plaintext or concrete flag candidate."
                                ],
                                "constraints": ["Use local files only."],
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)

    def test_planner_prioritizes_grounded_flag_validation_candidate(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        planner = LLMPlanner(
            StaticLLMClient(
                [
                    {
                        "summary": "more analysis",
                        "todos": [
                            {
                                "goal": "Review another artifact before flag recovery.",
                                "phase": "analysis",
                                "priority": 80,
                                "context": {},
                            }
                        ],
                        "notes": [],
                        "stop_run": False,
                    }
                ]
            )
        )
        decision = planner.plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(decision.todos[0].context["candidate_flag"], "flag{okay}")

    def test_planner_skips_llm_when_grounded_candidate_is_ready(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate

        def fail_if_called(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            raise AssertionError(
                "LLM should not be called for deterministic validation"
            )

        decision = LLMPlanner(StaticLLMClient(fail_if_called)).plan(state)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(decision.todos[0].context["candidate_flag"], "flag{okay}")
        self.assertIn("Skipped LLM planning", " ".join(decision.notes))

    def test_planner_keeps_flag_format_decryption_todo_as_analysis(self) -> None:

        def responder(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            return {
                "summary": "recover plaintext",
                "todos": [
                    {
                        "goal": "Write and execute a Python script that implements the LFSR decryption and prints the recovered flag{...} plaintext.",
                        "phase": "flag_validation",
                        "priority": 80,
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        decision = LLMPlanner(StaticLLMClient(responder)).plan(_state([]))
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)
        self.assertFalse(
            any(("ungrounded flag_validation" in note for note in decision.notes))
        )

    def test_planner_prompt_includes_stagnation_signals_without_blocking(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "summary": "try another analysis",
                "todos": [
                    {
                        "goal": "Try a different LFSR analysis path.",
                        "phase": "analysis",
                        "priority": 70,
                        "context": {"challenge_files": ["flag.enc"]},
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state([])
        partial = todo_queue(state).enqueue(
            TodoItem(
                goal="Decrypt the ciphertext and recover the flag.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="decrypt-once",
            )
        )
        todo_queue(state).start(partial, "exploit-worker")
        todo_queue(state).partial(
            partial,
            "Script execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
            "script exited successfully but no flag candidate was recovered",
        )
        planner = LLMPlanner(StaticLLMClient(responder))
        decision = planner.plan(state)
        signals = captured["snapshot"]["stagnation_signals"]
        self.assertEqual(signals["todo_status_counts"]["partial"], 1)
        self.assertEqual(len(signals["partial_todos"]), 1)
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)

    def test_planner_prompt_includes_recent_tool_evidence_context(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "summary": "use existing evidence",
                "todos": [],
                "notes": [],
                "stop_run": True,
            }

        state = _state([])
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-script",
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="Script execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
                extracted={
                    "output_context": {
                        "returncode": 0,
                        "result_quality": "partial_no_candidate",
                        "partial_reason": "script exited successfully but no flag candidate was recovered",
                        "failure_kind": "no_candidate",
                        "failure_detail": "script exited successfully but no flag candidate was recovered",
                        "stdout": "Raw hex of first 16 bytes: 535446556aab0223201f1e0a00008540\nLE uint32 at 4-7: 587377514\nLE uint32 at 8-11: 169746208\nLE uint32 at 12-15: 1082458112\n",
                        "flag_candidates": [],
                    }
                },
            )
        )
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-disasm",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Binary disassembly completed for 1 file(s): 1 function(s) kept, 0 flag candidate(s).",
                extracted={
                    "output_context": {
                        "inspected_binaries": ["stfu"],
                        "disassembly": {
                            "stfu": {
                                "binary_traits": {
                                    "arch": "i386",
                                    "stripped": True,
                                    "go_like": False,
                                },
                                "function_count_total": 23,
                                "function_count_kept": 1,
                                "disassembly_truncated": True,
                                "analysis_windows": [
                                    "804884d: xor ebx,eax\n804884f: and eax,0x1\n8048852: mov DWORD PTR [ebp-0xc],eax"
                                ],
                                "functions": [
                                    {
                                        "name": ".text",
                                        "size_lines": 181,
                                        "truncated": True,
                                        "xref_strings": [
                                            "Supplied tap values out of range",
                                            "STFU",
                                        ],
                                        "disassembly": "08048660 <.text>:\n 804884d: xor ebx,eax",
                                    }
                                ],
                            }
                        },
                        "flag_candidates": [],
                    }
                },
            )
        )
        StateDeltaApplier(state).apply(
            StateDelta(
                endpoints=[
                    Endpoint(
                        endpoint_id="endpoint-observed-tcp",
                        hostname="example.test",
                        port=8000,
                        protocol="tcp",
                        metadata={"service": "raw-tcp"},
                    )
                ]
            )
        )
        LLMPlanner(StaticLLMClient(responder)).plan(state)
        context = captured["snapshot"]["recent_evidence_context"]
        self.assertIsInstance(context, list)
        rendered = json.dumps(context)
        self.assertIn("535446556aab0223201f1e0a00008540", rendered)
        self.assertIn("partial_no_candidate", rendered)
        self.assertIn("no_candidate", rendered)
        self.assertIn("inspected_binaries", rendered)
        self.assertIn("stfu", rendered)
        self.assertIn(
            "endpoint-observed-tcp", json.dumps(captured["snapshot"]["endpoints"])
        )
        contract = captured["snapshot"]["planning_contract"]
        self.assertIn("/tmp files", contract["evidence_context_rule"])
        self.assertIn("partial_no_candidate", contract["evidence_quality_rule"])
        self.assertIn("diagnostic only", contract["evidence_quality_rule"])
        self.assertIn("open_todos is 0", contract["no_empty_noop_rule"])

    def test_planner_prompt_includes_structured_planning_profiles(self) -> None:
        captured: dict[str, object] = {}

        def responder(system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["system_prompt"] = system_prompt
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "matrix", "todos": [], "notes": [], "stop_run": True}

        LLMPlanner(StaticLLMClient(responder)).plan(_state(["chall.py"]))
        prompt = captured["system_prompt"]
        self.assertNotIn("CTF technique matrix", prompt)
        matrix = captured["snapshot"]["planning_profiles"]
        families = {item["family"] for item in matrix}
        self.assertIn("artifact-inventory", families)
        self.assertIn("crypto-model", families)
        self.assertIn("algorithm-verification", families)
        self.assertNotIn("web-exploit", families)
        self.assertTrue(all(("objective" not in item for item in matrix)))
        self.assertTrue(all(("failure_escape" not in item for item in matrix)))
        self.assertNotIn("ctf_technique_matrix", captured["snapshot"])
        self.assertNotIn("analysis_strategy", captured["snapshot"])
        self.assertNotIn("exploit_strategy", captured["snapshot"])
        self.assertNotIn("flag_recovery_hints", captured["snapshot"])

    def test_planner_prompt_includes_tracked_artifacts(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "artifacts", "todos": [], "notes": [], "stop_run": True}

        state = _state(["out.img"])
        StateDeltaApplier(state).apply(
            StateDelta(
                artifacts=[
                    Artifact(
                        path="/home/ctfplayer/ctf_files/.autopentest_artifacts/foremost_out/gif/00000000.gif",
                        kind="foremost_gif",
                        source="foremost",
                        size=1234,
                        metadata={"source_file": "/home/ctfplayer/ctf_files/out.img"},
                    )
                ]
            )
        )
        LLMPlanner(StaticLLMClient(responder)).plan(state)
        artifacts = captured["snapshot"]["artifacts"]
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0]["kind"], "foremost_gif")
        self.assertIn(".autopentest_artifacts", artifacts[0]["path"])
        self.assertEqual(artifacts[0]["size"], 1234)

    def test_planner_prompt_includes_structured_rejected_candidates(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "stop", "todos": [], "notes": [], "stop_run": True}

        state = _state([])
        StateDeltaApplier(state).apply(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(
                        value="flag{os.strerror(err) if err else 'Success'}",
                        source="script",
                    )
                ]
            )
        )
        LLMPlanner(StaticLLMClient(responder)).plan(state)
        rejected = captured["snapshot"]["rejected_flag_candidates"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "invalid_candidate_shape")

    def test_planner_prompt_bounds_mutable_state_sections(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "bounded", "todos": [], "notes": [], "stop_run": True}

        state = _state([])
        huge_text = "X" * 5000
        todo_queue(state).enqueue(
            TodoItem(
                goal="Analyze large generated context.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "crypto-decrypt",
                    "blob": huge_text,
                    "items": [f"item-{index}-" + huge_text for index in range(20)],
                    "nested": {"payload": huge_text},
                },
                dedupe_key="huge-context",
            )
        )
        state.run_memory["huge"] = huge_text
        state.execution_log.append(
            ExecutionRecord(
                task_id="todo-huge",
                worker_name="artifact-worker",
                success=False,
                summary=huge_text,
                error=huge_text,
            )
        )
        LLMPlanner(StaticLLMClient(responder)).plan(state)
        snapshot = captured["snapshot"]
        todo_context = snapshot["todos"][0]["context"]
        self.assertLessEqual(len(todo_context["blob"]), 400)
        self.assertIn("truncated", todo_context["blob"])
        self.assertEqual(len(todo_context["items"]), 8)
        self.assertLessEqual(len(todo_context["nested"]["payload"]), 400)
        self.assertLessEqual(len(snapshot["run_memory"]["huge"]), 400)
        execution_log = snapshot["recent_execution_log"]
        self.assertLessEqual(len(execution_log[0]["summary"]), 360)
        self.assertLessEqual(len(execution_log[0]["error"]), 260)
        self.assertNotIn("X" * 1000, json.dumps(snapshot))

    def test_planner_prompt_includes_credentials_and_sessions(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "bounded", "todos": [], "notes": [], "stop_run": True}

        state = _state([])
        state.credentials["cred-1"] = Credential(
            credential_id="cred-1",
            username="root",
            secret_ref="script-auth:root:***",
            credential_type="authenticated_access",
            source="script.exec",
            metadata={"target_url": "http://target.example/admin/"},
        )
        state.sessions["session-1"] = Session(
            session_id="session-1",
            username="root",
            session_type="authenticated_access",
            status="active",
            secret_ref="script-auth:root:***",
            metadata={"target_url": "http://target.example/admin/"},
        )

        LLMPlanner(StaticLLMClient(responder)).plan(state)
        snapshot = captured["snapshot"]
        self.assertEqual(snapshot["credentials"][0]["credential_id"], "cred-1")
        self.assertEqual(snapshot["credentials"][0]["username"], "root")
        self.assertEqual(snapshot["sessions"][0]["session_id"], "session-1")
        self.assertEqual(snapshot["sessions"][0]["status"], "active")


class PlannedTodoPriorityTests(unittest.TestCase):
    def test_string_priority_is_coerced(self) -> None:
        self.assertEqual(PlannedTodo(goal="x", priority="high").priority, 75)
        self.assertEqual(PlannedTodo(goal="x", priority="60").priority, 60)


if __name__ == "__main__":
    unittest.main()
