from __future__ import annotations

import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from killchain_docker.llm import StaticLLMClient
from killchain_docker.state import EvidenceRecord, RunState, TodoItem, TodoStatus
from killchain_docker.tools import (
    ExecutionMode,
    ExecutionPlane,
    ToolCapability,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
    jsonl_signal_parser,
)
from killchain_docker.tools.plugins import (
    binary_disassembly,
    binary_run,
    pcap_review,
    script_execution,
    source_review,
)
from killchain_docker.workers.persona import ExploitWorker, ReconWorker, WebWorker
from killchain_docker.workers.tool_metadata import normalize_tool_metadata


class _RecordingScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_execution"

    def __init__(self, returncode: int = 0, flag_candidates: list[str] | None = None) -> None:
        self.last_request: ToolExecutionRequest | None = None
        self.returncode = returncode
        self.flag_candidates = list(flag_candidates or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        candidate_count = len(self.flag_candidates)
        if self.returncode != 0:
            summary = (
                f"Script execution failed (exit {self.returncode}): "
                f"exit code {self.returncode}, 0 flag candidate(s)."
            )
        elif candidate_count:
            summary = f"Script execution succeeded: exit code 0, {candidate_count} flag candidate(s)."
        else:
            summary = "Script execution ran without recovering a flag: exit code 0, 0 flag candidate(s)."
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            stdout=(
                json.dumps({"type": "summary", "text": summary})
                + "\n"
                + json.dumps(
                    {
                        "type": "output_context",
                        "flag_candidates": self.flag_candidates,
                        "returncode": self.returncode,
                    }
                )
                + "\n"
            ),
        )


def _script_worker(plane: ExecutionPlane) -> ExploitWorker:
    return ExploitWorker(
        llm_client=StaticLLMClient([
            {
                "capability": "script.execute",
                "metadata": {},
                "rationale": "test-selected script execution",
                "expected_signal": "script output",
            },
            # ContinueDecision: inner loop should not continue after first step
            {"continue_loop": False, "reason": "single step sufficient"},
        ]),
        execution_plane=plane,
    )


class ToolMetadataNormalizationTests(unittest.TestCase):
    def test_non_script_worker_prompt_omits_script_execute_rules(self) -> None:
        captured: dict[str, str] = {}

        def responder(system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["system_prompt"] = system_prompt
            captured["user_prompt"] = user_prompt
            return {
                "capability": "http.metadata",
                "metadata": {"base_url": "http://safe.test"},
                "rationale": "read known page",
                "expected_signal": "http headers",
            }

        worker = ReconWorker(
            llm_client=StaticLLMClient(responder),
            execution_plane=ExecutionPlane(),
        )

        decision = worker.choose_tool_use(
            task=TodoItem(
                goal="Review known web content.",
                context={"base_url": "http://safe.test"},
            ),
            state=RunState(objective="solve", authorized_scope=["http://safe.test"]),
            allowed_capabilities=list(ReconWorker.allowed_capabilities),
        )

        self.assertEqual(decision.capability, "http.metadata")
        snapshot = json.loads(captured["user_prompt"])
        self.assertNotIn("script.execute", captured["system_prompt"])
        self.assertNotIn("script.execute", json.dumps(snapshot))
        self.assertNotIn("script.execute", snapshot["allowed_capabilities"])

    def test_script_worker_prompt_keeps_script_execute_rules(self) -> None:
        captured: dict[str, str] = {}

        def responder(system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["system_prompt"] = system_prompt
            captured["user_prompt"] = user_prompt
            return {
                "capability": "script.execute",
                "metadata": {"script_code": "print(1)"},
                "rationale": "run a bounded script",
                "expected_signal": "stdout",
            }

        worker = ExploitWorker(
            llm_client=StaticLLMClient(responder),
            execution_plane=ExecutionPlane(),
        )

        decision = worker.choose_tool_use(
            task=TodoItem(goal="Recover the flag with a script.", phase="analysis"),
            state=RunState(objective="solve"),
            allowed_capabilities=list(ExploitWorker.allowed_capabilities),
        )

        self.assertEqual(decision.capability, "script.execute")
        snapshot = json.loads(captured["user_prompt"])
        rendered = json.dumps(snapshot)
        self.assertNotIn("script.execute", captured["system_prompt"])
        self.assertIn("script.execute", snapshot["allowed_capabilities"])
        self.assertIn("For script.execute", rendered)

    def test_unavailable_script_execute_is_worker_failure_without_plugin_call(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin()
        plane.register_plugin(plugin)
        worker = ReconWorker(
            llm_client=StaticLLMClient([
                {
                    "capability": "script.execute",
                    "metadata": {"script_code": "print('should not run')"},
                    "rationale": "bad capability",
                    "expected_signal": "stdout",
                }
            ]),
            execution_plane=plane,
        )

        result = worker.run(
            TodoItem(
                goal="Review web content.",
                context={"base_url": "http://safe.test"},
            ),
            RunState(objective="solve", authorized_scope=["http://safe.test"]),
        )

        self.assertFalse(result.success)
        self.assertFalse(result.retryable)
        self.assertIn("recon-worker selected unavailable tool capability 'script.execute'", result.error or "")
        self.assertIn("allowed capabilities:", result.error or "")
        self.assertIsNone(plugin.last_request)

    def test_script_standard_metadata_only(self) -> None:
        state = RunState(objective="solve", metadata={"challenge": {"files": ["flag.enc"]}})
        todo = TodoItem(goal="run script", context={"script_code": "print(1)"})

        metadata = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXECUTE,
            todo,
            state,
            {"script_language": "python3"},
        )

        self.assertEqual(metadata["script_code"], "print(1)")
        self.assertEqual(metadata["script_language"], "python")

    def test_script_flag_format_comes_from_state_not_worker_metadata(self) -> None:
        state = RunState(
            objective="solve",
            metadata={"challenge": {"files": ["flag.stfu"], "flag_format": ""}},
        )
        todo = TodoItem(goal="run script", context={"script_code": "print('x')"})

        metadata = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXECUTE,
            todo,
            state,
            {"flag_format": r"flag\{[^}]+\}"},
        )

        self.assertEqual(metadata["flag_format"], "")

    def test_legacy_script_metadata_fails(self) -> None:
        state = RunState(objective="solve")
        legacy_contexts = [
            {"script_content": "print(1)"},
            {"python_code": "print(1)"},
            {"inline_python": "print(1)"},
            {"command": "echo old"},
        ]
        for context in legacy_contexts:
            with self.subTest(context=context):
                with self.assertRaises(ToolExecutionError):
                    normalize_tool_metadata(
                        ToolCapability.SCRIPT_EXECUTE,
                        TodoItem(goal="run legacy script", context=context),
                        state,
                        {},
                    )

    def test_file_standard_metadata_only(self) -> None:
        state = RunState(objective="solve", metadata={"challenge": {"files": ["capture.pcap", "server.py", "chall"]}})

        pcap_metadata = normalize_tool_metadata(
            ToolCapability.ARTIFACT_PCAP,
            TodoItem(goal="read pcap", context={"pcap_files": ["/home/ctfplayer/ctf_files/capture.pcap"]}),
            state,
            {},
        )
        source_metadata = normalize_tool_metadata(
            ToolCapability.ARTIFACT_SOURCE,
            TodoItem(goal="read source", context={"source_files": ["server.py"]}),
            state,
            {},
        )
        binary_metadata = normalize_tool_metadata(
            ToolCapability.ARTIFACT_BINARY_EXECUTE,
            TodoItem(goal="run binary", context={"binary_files": ["chall"]}),
            state,
            {},
        )

        self.assertEqual(pcap_metadata["pcap_files"], ["capture.pcap"])
        self.assertEqual(source_metadata["source_files"], ["server.py"])
        self.assertEqual(binary_metadata["binary_files"], ["chall"])

    def test_legacy_file_metadata_fails(self) -> None:
        state = RunState(objective="solve")
        legacy_cases = [
            (ToolCapability.ARTIFACT_SOURCE, {"source_file": "server.py"}),
            (ToolCapability.ARTIFACT_SOURCE, {"file_path": "server.py"}),
            (ToolCapability.ARTIFACT_SOURCE, {"target_file": "server.py"}),
            (ToolCapability.ARTIFACT_BINARY_EXECUTE, {"binary_file": "chall"}),
            (ToolCapability.ARTIFACT_PCAP, {"pcap_file": "capture.pcap"}),
        ]
        for capability, context in legacy_cases:
            with self.subTest(capability=capability, context=context):
                with self.assertRaises(ToolExecutionError):
                    normalize_tool_metadata(
                        capability,
                        TodoItem(goal="read old field", context=context),
                        state,
                        {},
                    )

    def test_missing_required_metadata_fails_before_plugin_call(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin()
        plane.register_plugin(plugin)
        worker = _script_worker(plane)
        state = RunState(objective="solve")
        todo = TodoItem(goal="exploit without target", phase="exploit")

        result = worker.run(todo, state)

        self.assertFalse(result.success)
        self.assertIn("script.execute missing required metadata.script_code", result.error or "")
        self.assertIsNone(plugin.last_request)

    def test_script_nonzero_returncode_fails_worker_result(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin(returncode=2)
        plane.register_plugin(plugin)
        worker = _script_worker(plane)
        state = RunState(objective="solve")
        todo = TodoItem(goal="run failing script", phase="exploit", context={"script_code": "raise SystemExit(2)"})

        result = worker.run(todo, state)

        self.assertFalse(result.success)
        self.assertIn("failed (exit 2)", result.summary)
        self.assertIsNotNone(plugin.last_request)

    def test_flag_recovery_script_without_candidate_is_partial(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin(returncode=0)
        plane.register_plugin(plugin)
        worker = _script_worker(plane)
        state = RunState(objective="solve")
        todo = state.queue_todo(
            TodoItem(
                goal="Decrypt the ciphertext and recover the flag.",
                phase="analysis",
                context={"script_code": "print('no flag yet')"},
            )
        )

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertTrue(result.success)
        self.assertTrue(result.partial)
        self.assertEqual(state.todos[0].status, TodoStatus.PARTIAL)

    def test_non_recovery_script_without_candidate_can_complete(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin(returncode=0)
        plane.register_plugin(plugin)
        worker = _script_worker(plane)
        state = RunState(objective="solve")
        todo = state.queue_todo(
            TodoItem(
                goal="Print the file header bytes.",
                phase="analysis",
                context={"script_code": "print('header')"},
            )
        )

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertTrue(result.success)
        self.assertFalse(result.partial)
        self.assertEqual(state.todos[0].status, TodoStatus.COMPLETED)

    def test_structured_error_candidate_is_not_added_to_state(self) -> None:
        bogus = "flag{'command': './stfu flag.stfu', 'error': \"[Errno 2] No such file or directory: 'strace'\"}"
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _RecordingScriptPlugin(returncode=0, flag_candidates=[bogus])
        plane.register_plugin(plugin)
        worker = _script_worker(plane)
        state = RunState(objective="solve")
        todo = state.queue_todo(
            TodoItem(
                goal="Run a diagnostic script.",
                phase="analysis",
                context={"script_code": "print('diagnostic')"},
            )
        )

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertTrue(result.success)
        self.assertEqual(state.flag_candidates, {})


class WorkerToolPromptEvidenceTests(unittest.TestCase):
    def test_worker_prompt_includes_compact_evidence_and_tmp_rule(self) -> None:
        captured: dict[str, str] = {}

        def responder(system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["system_prompt"] = system_prompt
            captured["user_prompt"] = user_prompt
            return {
                "capability": "script.execute",
                "metadata": {"script_code": "print('ok')", "script_language": "python"},
                "rationale": "Use grounded evidence.",
                "expected_signal": "stdout",
            }

        state = RunState(objective="solve")
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-script",
                capability="script.execute",
                tool_name="script_execution",
                mode="local_command",
                summary="Script execution failed (exit 1): exit code 1, 0 flag candidate(s).",
                extracted={
                    "output_context": {
                        "returncode": 1,
                        "result_quality": "failed",
                        "failure_kind": "syntax_error",
                        "failure_detail": "SyntaxError: unterminated string literal",
                        "stdout": "planned to read /tmp/full_stfu_disasm.txt\n",
                        "stderr": "SyntaxError: unterminated string literal\n",
                        "flag_candidates": [],
                    }
                },
            )
        )
        worker = ExploitWorker(
            llm_client=StaticLLMClient(responder),
            execution_plane=ExecutionPlane(),
        )

        decision = worker.choose_tool_use(
            task=TodoItem(goal="Recover the flag with a script.", phase="analysis"),
            state=state,
            allowed_capabilities=[ToolCapability.SCRIPT_EXECUTE],
        )

        self.assertEqual(decision.capability, "script.execute")
        snapshot = json.loads(captured["user_prompt"])
        rendered = json.dumps(snapshot)
        self.assertIn("recent_evidence_context", snapshot)
        self.assertIn("syntax_error", rendered)
        self.assertIn("unterminated string literal", rendered)
        self.assertIn("/tmp/full_stfu_disasm.txt", rendered)
        self.assertIn("Do not read /tmp paths created by previous todos.", rendered)
        self.assertIn("Do not depend on /tmp files", captured["system_prompt"])


class StrictPluginContractTests(unittest.TestCase):
    def _run_plugin(self, module, metadata: dict[str, object]) -> subprocess.CompletedProcess[str]:
        request = ToolExecutionRequest(
            tool_name=module.TOOL_NAME,
            parser_name="jsonl_signals",
            timeout_s=20,
            metadata=metadata,
        )
        return subprocess.run(
            ["python3", *module.build_arguments(request)],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )

    def test_script_execution_empty_script_code_fails(self) -> None:
        result = self._run_plugin(script_execution, {"script_code": ""})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing required metadata.script_code", result.stdout)
        self.assertNotIn("skipped", result.stdout.lower())

    def test_script_execution_reports_partial_quality_without_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run_plugin(
                script_execution,
                {
                    "files_root": tmp,
                    "script_code": "print('analysis only')",
                    "script_language": "python",
                },
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn('"result_quality": "partial_no_candidate"', result.stdout)
        self.assertIn('"partial_reason": "script exited successfully but no flag candidate was recovered"', result.stdout)
        self.assertIn('"failure_kind": "no_candidate"', result.stdout)

    def test_file_plugins_empty_targets_fail(self) -> None:
        cases = [
            (source_review, {"source_files": []}, "metadata.source_files"),
            (pcap_review, {"pcap_files": []}, "metadata.pcap_files"),
            (binary_run, {"binary_files": []}, "metadata.binary_files"),
        ]
        for module, metadata, expected in cases:
            with self.subTest(module=module.TOOL_NAME):
                result = self._run_plugin(module, metadata)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stdout)

    def test_source_review_missing_requested_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = self._run_plugin(
                source_review,
                {"files_root": tmp, "source_files": ["missing.py"]},
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no requested source files could be read", result.stdout)

    def test_binary_disassembly_script_exposes_traits_and_windows(self) -> None:
        self.assertIn('"binary_traits"', binary_disassembly.SCRIPT)
        self.assertIn('"go_like"', binary_disassembly.SCRIPT)
        self.assertIn('"analysis_windows"', binary_disassembly.SCRIPT)
        self.assertIn('"disassembly_truncated"', binary_disassembly.SCRIPT)

    def test_source_review_expands_exact_directory_glob_and_archive_member(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "server.py").write_text("ROUTE = '/admin'\n", encoding="utf-8")
            (src / "notes.txt").write_text("password = 'secret'\n", encoding="utf-8")
            archive_path = root / "bundle.tar"
            archived_file = root / "archived.py"
            archived_file.write_text("TOKEN = 'abc'\n", encoding="utf-8")
            with tarfile.open(archive_path, "w") as tf:
                tf.add(archived_file, arcname="pkg/archived.py")

            directory_result = self._run_plugin(
                source_review,
                {"files_root": tmp, "source_files": ["src"]},
            )
            glob_result = self._run_plugin(
                source_review,
                {"files_root": tmp, "source_files": ["**/*.py"]},
            )
            archive_result = self._run_plugin(
                source_review,
                {"files_root": tmp, "source_files": ["bundle.tar:pkg/archived.py"]},
            )

        for result in (directory_result, glob_result, archive_result):
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Source review completed", result.stdout)


if __name__ == "__main__":
    unittest.main()
