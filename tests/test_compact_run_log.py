from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from killchain_docker.controller import (
    EventRecorder,
    RunPersister,
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

    def test_persister_writes_compact_files_on_checkpoint(self) -> None:
        state = self._state_with_round()

        with tempfile.TemporaryDirectory() as tmp:
            recorder = EventRecorder(quiet=True)
            recorder.emit("[cycle 1] ok todo -> artifact-worker")
            persister = RunPersister(Path(tmp), recorder)

            persister.write_state(state)

            compact_json = json.loads(persister.compact_json_path.read_text(encoding="utf-8"))
            compact_md = persister.compact_markdown_path.read_text(encoding="utf-8")
            self.assertEqual(compact_json["run"]["run_id"], state.run_id)
            self.assertEqual(compact_json["counts"]["rounds"], 1)
            self.assertIn("Compact Run Log", compact_md)
            self.assertIn("Cycle 1", compact_md)


if __name__ == "__main__":
    unittest.main()
