from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import StaticLLMClient, TokenLedger
from killchain_docker.controller import (
    EventRecorder,
    RunConfig,
    RunPersister,
    RuntimeStatusHeartbeat,
    build_runtime,
    build_compact_run_log,
    render_compact_run_markdown,
)
from killchain_docker.state import (
    RouterRound,
    RouterRoundSummary,
    RunState,
    TodoItem,
    WorkerAssignment,
    WorkerResult,
)


class CompactRunLogTests(unittest.TestCase):
    def _state_with_round(self) -> RunState:
        state = RunState(
            objective="Solve compact logging challenge",
            metadata={
                "challenge": {
                    "canonical_name": "fake-crypto",
                    "name": "fake",
                    "category": "crypto",
                    "flag_format": "flag{...}",
                    "files": ["chall", "flag.enc"],
                }
            },
        )
        todo = state.queue_todo(
            TodoItem(
                goal="Inspect bundled files and recover the flag with a short script.",
                phase="analysis",
                context={"family": "artifact-triage"},
            )
        )
        assignment = WorkerAssignment(
            todo_id=todo.todo_id,
            worker_name="artifact-worker",
            rationale="local files",
        )
        todo.mark_running("artifact-worker")
        result = WorkerResult(
            todo_id=todo.todo_id,
            worker_name="artifact-worker",
            success=True,
            summary="Artifact triage completed for /home/ctfplayer/ctf_files: 2 file(s), 0 flag candidate(s).",
        )
        state.apply_worker_result(result)
        state.record_round(
            RouterRound(
                cycle=1,
                planner_summary="Start by triaging local artifacts and checking for an encrypted flag file.",
                assignments=[assignment],
                results=[result],
                summary=RouterRoundSummary(
                    summary="artifact-worker completed local artifact triage",
                    key_findings=["Two local files were present."],
                    next_focus="Reverse the encryption format.",
                ),
            )
        )
        state.working_memory["format"] = "Encrypted file with a short binary companion."
        return state

    def test_compact_payload_and_markdown_capture_timeline(self) -> None:
        state = self._state_with_round()

        payload = build_compact_run_log(state, events=["[cycle 1] ok todo -> artifact-worker"])
        markdown = render_compact_run_markdown(payload)

        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["challenge"]["canonical_name"], "fake-crypto")
        self.assertEqual(payload["timeline"][0]["cycle"], 1)
        self.assertIn("artifact-worker", markdown)
        self.assertIn("Reverse the encryption format", markdown)
        self.assertIn("state.json", markdown)

    def test_compact_log_surfaces_runtime_error(self) -> None:
        state = self._state_with_round()
        state.metadata["runtime_error"] = {
            "type": "RuntimeError",
            "message": "router crashed before finalizing state",
        }

        payload = build_compact_run_log(state)
        markdown = render_compact_run_markdown(payload)

        self.assertEqual(payload["run"]["runtime_error"]["type"], "RuntimeError")
        self.assertIn("Runtime error", markdown)
        self.assertIn("router crashed before finalizing state", markdown)

    def test_compact_markdown_surfaces_public_rag_status(self) -> None:
        state = self._state_with_round()
        state.metadata["rag"] = {
            "mode": "strict",
            "enabled": True,
            "status": "hit",
            "knowledge_hints": [{"solution_sketch": "raw hint"}],
            "hit_provenance": [{"challenge_id": "hidden"}],
        }

        payload = build_compact_run_log(state)
        markdown = render_compact_run_markdown(payload)

        self.assertEqual(payload["rag"]["policy"], "filtered_context")
        self.assertIn("## RAG", markdown)
        self.assertIn("status=`hit`", markdown)
        self.assertIn("policy=`filtered_context`", markdown)
        self.assertIn("hints=1", markdown)
        self.assertNotIn("hidden", markdown)

    def test_persister_summary_uses_public_rag_payload(self) -> None:
        state = self._state_with_round()
        state.metadata["rag"] = {
            "mode": "strict",
            "enabled": True,
            "status": "hit",
            "knowledge_hints": [{"solution_sketch": "raw hint"}],
            "hit_provenance": [{"challenge_id": "hidden"}],
        }

        with tempfile.TemporaryDirectory() as tmp:
            persister = RunPersister(Path(tmp), EventRecorder(quiet=True))
            persister.write_all(state)

            summary = json.loads(persister.summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["rag"]["policy"], "filtered_context")
            self.assertEqual(summary["rag"]["hint_count"], 1)
            self.assertNotIn("mode", summary["rag"])
            self.assertNotIn("knowledge_hints", summary["rag"])
            self.assertNotIn("hit_provenance", summary["rag"])

    def test_persister_writes_compact_files_on_checkpoint(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            recorder = EventRecorder(quiet=True)
            recorder.bind_context(run_id=state.run_id, challenge="fake-crypto")
            recorder.emit("[cycle 1] ok todo -> artifact-worker")
            persister = RunPersister(Path(tmp), recorder)

            persister.write_state(state)

            compact_json = json.loads(persister.compact_json_path.read_text(encoding="utf-8"))
            compact_md = persister.compact_markdown_path.read_text(encoding="utf-8")
            event = json.loads(persister.events_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(compact_json["run"]["run_id"], state.run_id)
            self.assertEqual(compact_json["counts"]["rounds"], 1)
            self.assertEqual(event["event_type"], "runtime")
            self.assertEqual(event["message"], "[cycle 1] ok todo -> artifact-worker")
            self.assertIsInstance(event["thread_name"], str)
            self.assertEqual(event["context"]["run_id"], state.run_id)
            self.assertEqual(event["context"]["challenge"], "fake-crypto")
            self.assertIn("Compact Run Log", compact_md)
            self.assertIn("Cycle 1", compact_md)

    def test_persister_stringifies_non_json_event_context(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            context_path = Path(tmp) / "artifact.bin"
            recorder = EventRecorder(quiet=True)
            recorder.emit("event with path context", artifact_path=context_path)
            persister = RunPersister(Path(tmp) / "run", recorder)

            persister.write_state(state)

            self.assertEqual(recorder.records[0]["context"]["artifact_path"], str(context_path))
            event = json.loads(persister.events_path.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(event["context"]["artifact_path"], str(context_path))

    def test_event_recorder_records_are_isolated_snapshots(self) -> None:
        recorder = EventRecorder(quiet=True)
        recorder.emit("event with nested context", payload={"items": ["original"]})

        snapshot = recorder.records
        snapshot[0]["context"]["payload"]["items"].append("mutated")

        self.assertEqual(
            recorder.records[0]["context"]["payload"],
            {"items": ["original"]},
        )

    def test_event_recorder_handles_circular_context(self) -> None:
        payload: dict[str, object] = {}
        payload["self"] = payload
        recorder = EventRecorder(quiet=True)

        recorder.emit("event with circular context", payload=payload)

        self.assertEqual(
            recorder.records[0]["context"]["payload"],
            {"self": "[circular]"},
        )

    def test_persister_checkpoint_failure_logs_traceback_event(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            recorder = EventRecorder(quiet=True)
            persister = RunPersister(Path(tmp) / "run", recorder)

            with patch("killchain_docker.controller._write_json", side_effect=OSError("disk full")):
                with self.assertLogs("killchain_docker.controller", level="ERROR") as captured:
                    persister.write_state(state)

            self.assertIsNotNone(captured.records[0].exc_info)
            event = recorder.records[-1]
            self.assertEqual(event["level"], "ERROR")
            self.assertEqual(event["event_type"], "persistence")
            self.assertIn("checkpoint write failed", event["message"])

    def test_event_recorder_logs_structured_event_context(self) -> None:
        recorder = EventRecorder(quiet=False)
        recorder.bind_context(run_id="run-1", challenge="demo")

        with self.assertLogs("killchain_docker.controller", level="INFO") as captured:
            recorder.emit("[cycle 1] plan: inspect files", event_sequence="bad-context")

        record = captured.records[0]
        self.assertEqual(record.event_type, "planner")
        self.assertEqual(record.event_sequence, 1)
        self.assertIsInstance(record.event_pid, int)
        self.assertIsInstance(record.event_thread_id, int)
        self.assertIsInstance(record.event_thread_name, str)
        self.assertEqual(record.run_id, "run-1")
        self.assertEqual(record.challenge, "demo")

    def test_persister_updates_runtime_status_on_checkpoint(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "fake-crypto.status.json"
            recorder = EventRecorder(quiet=True)
            recorder.emit("[cycle 1] ok todo -> artifact-worker")
            token_ledger = TokenLedger()
            token_ledger.record(10, 5)
            persister = RunPersister(Path(tmp) / "run", recorder, status_path, token_ledger)
            state.metadata["rag"] = {"mode": "strict", "status": "hit"}

            persister.write_state(state)

            status = json.loads(status_path.read_text(encoding="utf-8"))
            compact = json.loads(persister.compact_json_path.read_text(encoding="utf-8"))
            self.assertEqual(status["schema_version"], 1)
            self.assertEqual(status["run_id"], state.run_id)
            self.assertEqual(status["stage"], "assessment")
            self.assertEqual(status["token_usage"]["llm_calls"], 1)
            self.assertEqual(status["token_usage"]["total_tokens"], 15)
            self.assertEqual(compact["token_usage"]["completion_tokens"], 5)
            self.assertIsInstance(status["thread_id"], int)
            self.assertIsInstance(status["thread_name"], str)
            self.assertIsInstance(status["status_writer_thread_id"], int)
            self.assertIsInstance(status["status_writer_thread_name"], str)
            self.assertEqual(status["threads"]["observed"]["id"], status["thread_id"])
            self.assertEqual(status["threads"]["observed"]["name"], status["thread_name"])
            self.assertEqual(status["threads"]["status_writer"]["id"], status["status_writer_thread_id"])
            self.assertEqual(
                status["threads"]["status_writer"]["name"],
                status["status_writer_thread_name"],
            )
            self.assertEqual(status["threads"]["latest_event"]["id"], status["latest_event"]["thread_id"])
            self.assertEqual(status["threads"]["latest_event"]["name"], status["latest_event"]["thread_name"])
            registry = status["threads"]["registry"]
            self.assertTrue(registry)
            self.assertEqual(registry[0]["challenge"], "fake-crypto")
            self.assertIn("latest_event", registry[0])
            self.assertIn("state_updated_at", status)
            self.assertIsInstance(status["runtime_sec"], (float, int))
            self.assertGreaterEqual(status["runtime_sec"], 0)
            self.assertEqual(status["latest_event"]["event_type"], "runtime")
            self.assertIsInstance(status["latest_event"]["thread_id"], int)
            self.assertIsInstance(status["latest_event"]["thread_name"], str)
            self.assertEqual(status["rag"]["policy"], "filtered_context")
            self.assertNotIn("mode", status["rag"])
            self.assertIn("compact_log.json", status["artifacts"]["compact_json_path"])
            self.assertFalse(Path(status["artifacts"]["compact_json_path"]).is_absolute())

    def test_runtime_status_omits_artifacts_outside_status_root(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            status_path = root / "logs" / "fake-crypto.status.json"
            run_dir = root / "external-artifacts" / "run-1"
            persister = RunPersister(run_dir, EventRecorder(quiet=True), status_path)

            persister.write_runtime_status(state, stage="assessment")

            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertNotIn("run_dir", status)
            self.assertEqual(status["artifacts"], {})

    def test_runtime_status_prefers_running_todo_over_latest_todo(self) -> None:
        state = RunState(objective="Solve status ordering")
        running = state.queue_todo(TodoItem(goal="Currently running analysis", phase="analysis"))
        running.mark_running("analysis-worker")
        state.queue_todo(TodoItem(goal="Queued follow-up", phase="analysis"))

        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "status.json"
            persister = RunPersister(Path(tmp) / "run", EventRecorder(quiet=True), status_path)

            persister.write_runtime_status(state, stage="assessment")

            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertEqual(status["current_todo"]["todo_id"], running.todo_id)
            self.assertEqual(status["current_todo"]["worker"], "analysis-worker")
            self.assertEqual(status["threads"]["registry"][0]["current_todo"]["todo_id"], running.todo_id)

    def test_runtime_status_registry_tracks_multiple_event_threads(self) -> None:
        state = self._state_with_round()
        recorder = EventRecorder(quiet=True)
        barrier = threading.Barrier(3)

        def emit(name: str) -> None:
            barrier.wait(timeout=2)
            recorder.emit(
                f"{name} progress",
                event_type=name,
                cycle=3,
                todo_id=f"todo-{name}",
                todo_phase="analysis",
                todo_status="running",
                worker=name,
            )

        threads = [
            threading.Thread(target=emit, args=("worker-a",), name="worker-a"),
            threading.Thread(target=emit, args=("worker-b",), name="worker-b"),
        ]
        for thread in threads:
            thread.start()
        barrier.wait(timeout=2)
        for thread in threads:
            thread.join()

        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "status.json"
            persister = RunPersister(Path(tmp) / "run", recorder, status_path)

            persister.write_runtime_status(state, stage="assessment")

            status = json.loads(status_path.read_text(encoding="utf-8"))
            registry = {entry["name"]: entry for entry in status["threads"]["registry"]}
            self.assertIn("worker-a", registry)
            self.assertIn("worker-b", registry)
            self.assertIn("event_source", registry["worker-a"]["roles"])
            self.assertEqual(registry["worker-a"]["latest_event"]["event_type"], "worker-a")
            self.assertEqual(registry["worker-a"]["current_todo"]["todo_id"], "todo-worker-a")
            self.assertEqual(registry["worker-a"]["current_todo"]["worker"], "worker-a")
            self.assertIn("event_source", registry["worker-b"]["roles"])
            self.assertEqual(registry["worker-b"]["latest_event"]["event_type"], "worker-b")
            self.assertEqual(registry["worker-b"]["current_todo"]["todo_id"], "todo-worker-b")
            self.assertEqual(registry["worker-b"]["current_todo"]["worker"], "worker-b")

    def test_runtime_status_omits_completed_todo_as_current_work(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "status.json"
            recorder = EventRecorder(quiet=True)
            recorder.emit("[cycle 2] planning next todos")
            persister = RunPersister(Path(tmp) / "run", recorder, status_path)

            persister.write_runtime_status(state, stage="assessment")

            status = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertIsNone(status["current_todo"])
            self.assertEqual(status["message"], "[cycle 2] planning next todos")

    def test_runtime_status_heartbeat_refreshes_status_timestamp(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            status_path = Path(tmp) / "fake-crypto.status.json"
            recorder = EventRecorder(quiet=True)
            recorder.bind_context(run_id=state.run_id, challenge="fake-crypto")
            recorder.emit("[cycle 1] waiting on LLM")
            token_ledger = TokenLedger()
            token_ledger.record(1, 2)
            persister = RunPersister(Path(tmp) / "run", recorder, status_path, token_ledger)
            persister.write_runtime_status(state, stage="assessment")
            first = json.loads(status_path.read_text(encoding="utf-8"))
            token_ledger.record(3, 4)

            heartbeat = RuntimeStatusHeartbeat(persister, state, interval_s=0.05)
            heartbeat.start()
            try:
                time.sleep(0.14)
            finally:
                heartbeat.stop()

            second = json.loads(status_path.read_text(encoding="utf-8"))
            self.assertNotEqual(first["updated_at"], second["updated_at"])
            self.assertEqual(first["state_updated_at"], second["state_updated_at"])
            self.assertGreaterEqual(second["runtime_sec"], first["runtime_sec"])
            self.assertEqual(second["latest_event"]["message"], "[cycle 1] waiting on LLM")
            self.assertEqual(first["token_usage"]["total_tokens"], 3)
            self.assertEqual(second["token_usage"]["total_tokens"], 10)

    def test_build_runtime_passes_explicit_rag_mode(self) -> None:
        config = RunConfig(
            objective="fake objective",
            authorized_scope=[],
            rag_mode="strict",
        )
        augmenter = KnowledgeAugmenter(None, mode="strict")

        with patch(
            "killchain_docker.controller.KnowledgeAugmenter.from_default",
            return_value=augmenter,
        ) as from_default:
            state, _orchestrator, _client = build_runtime(
                config,
                llm_client=StaticLLMClient([{}]),
            )

        from_default.assert_called_once_with(mode="strict")
        self.assertEqual(state.metadata["rag"]["mode"], "strict")


if __name__ == "__main__":
    unittest.main()
