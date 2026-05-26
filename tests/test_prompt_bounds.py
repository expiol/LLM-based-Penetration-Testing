"""Prompt bounding invariants for LLM-facing agent payloads."""

from __future__ import annotations
import json
import unittest
from killchain_docker.llm.gateway import StaticLLMClient
from killchain_docker.prompt_projection import (
    planner_todo,
    router_todo,
    worker_todo,
    run_memory,
)
from killchain_docker.prompts.planner import build_planner_system_prompt
from killchain_docker.state.domain import Artifact, EvidenceRecord, ExecutionRecord
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.worker_agent import WorkerAgent
from killchain_docker.workers.correction_instructions import (
    script_correction_instruction,
)


class _PromptWorker(WorkerAgent):
    name = "prompt-worker"
    supported_todo_kinds = ("todo",)

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id, worker_name=self.name, success=True, summary="unused"
        )


class WorkerPromptBoundsTests(unittest.TestCase):
    def test_planner_prompt_keeps_evaluation_terms_out_of_summaries(self) -> None:
        prompt = build_planner_system_prompt("crypto")
        self.assertIn("technical rationale only", prompt)
        self.assertIn("mode labels", prompt)
        self.assertIn("writeups", prompt)
        self.assertIn("similarity", prompt)
        self.assertIn("knowledge hints", prompt)
        self.assertIn("source identity labels", prompt)
        self.assertIn("authorized_scope", prompt)
        self.assertIn("localhost", prompt)
        for disallowed in (
            "RSA with small primes",
            "known-plaintext attacks",
            "ltrace/strace",
            "binwalk",
            "steghide",
            "execution-closure",
            "score bounded interpretations",
            "format-appropriate semantics",
            "CTF technique matrix",
        ):
            self.assertNotIn(disallowed, prompt)

    def test_prompt_projection_profiles_share_bounding_rules(self) -> None:
        huge_text = "X" * 5000
        state = RunState(objective="Solve.")
        state.run_memory["huge"] = huge_text
        todo = TodoItem(
            goal=huge_text,
            context={
                "blob": huge_text,
                "items": [huge_text for _ in range(20)],
                "dispatch_intent": {
                    "profile": "execution_closure",
                    "completion_contract": ["legacy_contract"],
                    "repair_policy_id": "legacy_repair",
                },
            },
        )
        planner_projection = planner_todo(todo)
        router_projection = router_todo(todo)
        worker_projection = worker_todo(todo)
        self.assertNotIn(
            "completion_contract", planner_projection["context"]["dispatch_intent"]
        )
        self.assertNotIn(
            "repair_policy_id", planner_projection["context"]["dispatch_intent"]
        )
        self.assertLessEqual(len(router_projection["goal"]), 400)
        self.assertLessEqual(len(router_projection["context"]["blob"]), 400)
        self.assertLessEqual(len(worker_projection["goal"]), 460)
        self.assertLessEqual(len(worker_projection["context"]["blob"]), 460)
        self.assertEqual(len(router_projection["context"]["items"]), 8)
        self.assertEqual(len(worker_projection["context"]["items"]), 8)
        self.assertNotIn(
            "completion_contract", router_projection["context"]["dispatch_intent"]
        )
        self.assertNotIn(
            "repair_policy_id", worker_projection["context"]["dispatch_intent"]
        )
        self.assertNotIn("completion_contract", router_projection["dispatch_intent"])
        self.assertNotIn("repair_policy_id", worker_projection["dispatch_intent"])
        self.assertLessEqual(len(run_memory(state)["huge"]), 400)

    def test_worker_tool_selection_prompt_bounds_state_sections(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "shell.exec",
                "metadata": {"command": "true"},
                "rationale": "bounded",
                "expected_signal": "exit 0",
            }

        huge_text = "X" * 5000
        state = RunState(objective="Solve.")
        state.run_memory["huge"] = huge_text
        state.artifacts["artifact-large"] = Artifact(
            artifact_id="artifact-large",
            path="/home/ctfplayer/ctf_files/.autopentest_artifacts/" + huge_text,
            kind="foremost_gif",
            source="foremost",
            size=12,
        )
        state.metadata["rag"] = {
            "knowledge_hints": [
                {
                    "rank": 1,
                    "category": "crypto",
                    "solution_sketch": "REFERENCE-CODE\nprint('ok')",
                    "score": 0.99,
                    "challenge_id": "hidden-source-id",
                },
                {"rank": 2, "category": "crypto", "solution_sketch": "second"},
                {"rank": 3, "category": "crypto", "solution_sketch": "third"},
                {"rank": 4, "category": "crypto", "solution_sketch": "fourth"},
            ]
        }
        state.execution_log.append(
            ExecutionRecord(
                task_id="todo-huge",
                worker_name="artifact-worker",
                success=False,
                summary=huge_text,
                error=huge_text,
            )
        )
        task = TodoItem(
            goal="Choose a bounded script tool call to decrypt data.",
            context={
                "family": "crypto-decrypt",
                "blob": huge_text,
                "items": [huge_text for _ in range(20)],
            },
        )
        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=task,
            state=state,
            allowed_capabilities=[
                ToolCapability.SHELL_EXEC,
                ToolCapability.SCRIPT_EXEC,
            ],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": huge_text,
                    "stderr_preview": huge_text,
                    "flag_candidates": [],
                    "returncode": 1,
                    "failure_kind": "no_candidate",
                }
            ],
        )
        snapshot = captured["snapshot"]
        todo_context = snapshot["todo"]["context"]
        self.assertLessEqual(len(todo_context["blob"]), 460)
        self.assertEqual(len(todo_context["items"]), 8)
        artifacts = snapshot["artifacts"]
        self.assertEqual(artifacts[0]["kind"], "foremost_gif")
        self.assertLessEqual(len(artifacts[0]["path"]), 460)
        self.assertLessEqual(len(snapshot["run_memory"]["huge"]), 400)
        self.assertNotIn("knowledge_hints", snapshot)
        self.assertNotIn("REFERENCE-CODE", json.dumps(snapshot))
        self.assertNotIn("solution_sketch", json.dumps(snapshot))
        self.assertNotIn("challenge_id", json.dumps(snapshot))
        recent_failures = snapshot["recent_failures"]
        self.assertLessEqual(len(recent_failures[0]["summary"]), 360)
        prior_steps = snapshot["prior_steps"]
        self.assertLessEqual(len(prior_steps[0]["stdout_preview"]), 740)
        correction_context = snapshot["correction_context"]
        self.assertLessEqual(len(correction_context["last_stdout"]), 740)
        self.assertIn("last_traceback", correction_context["instruction"])
        rules = "\n".join(snapshot["tool_use_rules"])
        self.assertIn("bound loops", rules)
        self.assertIn("third-party Python packages", rules)
        self.assertIn("Prefer stdlib", rules)
        self.assertIn("ImportError", rules)
        self.assertIn("stdlib fallback", rules)
        self.assertIn("connect/read socket timeouts <=5 seconds", rules)
        self.assertIn("localhost/127.0.0.1", rules)
        self.assertIn("explicit challenge paths", rules)
        self.assertIn("CTF_ORIGINAL_FILES_ROOT is a separate pristine snapshot", rules)
        self.assertIn("main()", rules)
        self.assertIn("ast.parse", rules)
        self.assertNotIn("candidate provenance", rules)
        self.assertNotIn("format-appropriate semantics", rules)
        self.assertNotIn("low-quality possible candidate", rules)
        self.assertNotIn("search the full plaintext", rules)
        self.assertNotIn("low-quality possible flag", correction_context["instruction"])
        catalog = json.dumps(snapshot["tool_catalog"])
        self.assertIn("bounded source", catalog)
        self.assertNotIn("reflexion_context", snapshot)
        self.assertNotIn("X" * 1000, json.dumps(snapshot))

    def test_worker_tool_selection_keeps_artifact_projection_task_relevant(
        self,
    ) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["user_prompt"] = user_prompt
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "print('bounded')"},
                "rationale": "bounded",
                "expected_signal": "concise diagnostics",
            }

        huge_text = "X" * 5000
        state = RunState(objective="Solve.")
        target_paths: list[str] = []
        for index in range(40):
            path = f"/home/ctfplayer/ctf_files/.autopentest_artifacts/batch_{index}/scratch/item_{index}.bin"
            artifact_id = f"artifact-{index}"
            state.artifacts[artifact_id] = Artifact(
                artifact_id=artifact_id,
                path=path,
                kind="script_artifact",
                source="script_exec",
                size=index + 1,
                digest=f"digest-{index}",
                preview=huge_text,
                metadata={
                    "relative_path": f"scratch/item_{index}.bin",
                    "file_type": "data",
                    "mime_type": "application/octet-stream",
                    "interesting_strings": [huge_text for _ in range(10)],
                    "irrelevant_blob": huge_text,
                    "evidence_ids": [f"evidence-{index}"],
                },
            )
            if index in {3, 17, 29}:
                target_paths.append(path)
        state.evidence["evidence-17"] = EvidenceRecord(
            evidence_id="evidence-17",
            task_id="prior",
            capability="script.exec",
            tool_name="script_exec",
            mode="local_command",
            summary="script (python)",
            extracted={
                "output_context": {
                    "returncode": 0,
                    "result_quality": "partial_no_candidate",
                    "failure_kind": "no_candidate",
                    "failure_detail": "script exited successfully but no flag candidate was recovered",
                    "stdout": "line with useful key material\n" + huge_text,
                }
            },
        )
        task = TodoItem(
            goal="Use referenced generated artifacts to continue bounded local analysis.",
            context={
                "family": "algorithm-verification",
                "artifact_ids": ["artifact-3"],
                "paths": target_paths,
                "prior_evidence_ids": ["evidence-17"],
                "dispatch_intent": {
                    "profile": "execution_closure",
                    "required_capability": "script.exec",
                },
            },
        )
        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=task, state=state, allowed_capabilities=[ToolCapability.SCRIPT_EXEC]
        )
        snapshot = captured["snapshot"]
        payload_text = captured["user_prompt"]
        self.assertLessEqual(len(payload_text), 18000)
        artifacts = snapshot["artifacts"]
        artifact_ids = {artifact["artifact_id"] for artifact in artifacts}
        self.assertLessEqual(len(artifacts), 10)
        self.assertIn("artifact-3", artifact_ids)
        self.assertIn("artifact-17", artifact_ids)
        self.assertIn("artifact-29", artifact_ids)
        self.assertNotIn("irrelevant_blob", json.dumps(artifacts))
        self.assertNotIn("X" * 1000, payload_text)

    def test_shell_python_syntax_failure_requests_script_exec(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "print('fixed')"},
                "rationale": "use multiline script",
                "expected_signal": "runs",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(goal="Parse a binary header with Python."),
            state=RunState(objective="Solve."),
            allowed_capabilities=[
                ToolCapability.SHELL_EXEC,
                ToolCapability.SCRIPT_EXEC,
            ],
            prior_steps=[
                {
                    "capability": "shell.exec",
                    "stdout_preview": "",
                    "stderr_preview": "SyntaxError: invalid syntax",
                    "returncode": 1,
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertIn("choose script.exec", correction["instruction"])
        rules = "\n".join(captured["snapshot"]["tool_use_rules"])
        self.assertIn("complex Python one-liners", rules)

    def test_script_syntax_failure_includes_raw_traceback(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "def main():\n    print('fixed')\nmain()"},
                "rationale": "fix syntax",
                "expected_signal": "script parses",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(goal="Repair generated Python solver syntax."),
            state=RunState(objective="Solve."),
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "",
                    "traceback": "Traceback (most recent call last):\n  File \"/workspace/solver.py\", line 1\nSyntaxError: 'return' outside function",
                    "stderr_preview": "SyntaxError: 'return' outside function",
                    "returncode": 1,
                    "failure_kind": "syntax_error",
                    "failure_detail": "script failed Python syntax validation",
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertIn("last_traceback", correction["instruction"])
        self.assertIn("Correct the syntax", correction["instruction"])
        self.assertIn(
            "Traceback (most recent call last):", correction["last_traceback"]
        )

    def test_bytes_text_failure_exposes_raw_feedback_without_recipe(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "def main():\n    print('fixed')\nmain()"},
                "rationale": "fix bytes",
                "expected_signal": "script handles binary data",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(goal="Repair generated Python XOR solver."),
            state=RunState(objective="Solve."),
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "",
                    "stderr_preview": "TypeError: byte indices must be integers or slices, not str",
                    "returncode": 1,
                    "failure_kind": "bytes_text_mismatch",
                    "failure_detail": "script mixed bytes and text across an IO boundary",
                }
            ],
        )
        snapshot = captured["snapshot"]
        correction = snapshot["correction_context"]
        self.assertEqual(correction["failure_kind"], "bytes_text_mismatch")
        self.assertIn("TypeError: byte indices", correction["last_stderr"])
        self.assertIn("traceback line", correction["instruction"])
        rules = "\n".join(snapshot["tool_use_rules"])
        self.assertNotIn("bytes.fromhex()", rules)
        self.assertNotIn("integer-safe XOR helpers", rules)

    def test_path_type_failure_requests_consistent_path_api(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {
                    "script_code": "from pathlib import Path\nprint(Path('.'))"
                },
                "rationale": "fix path API",
                "expected_signal": "script builds paths",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(goal="Repair generated Python artifact solver paths."),
            state=RunState(objective="Solve."),
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "",
                    "stderr_preview": "TypeError: unsupported operand type(s) for /: 'str' and 'str'",
                    "returncode": 1,
                    "failure_kind": "path_type_mismatch",
                    "failure_detail": "script mixed string paths with pathlib operations",
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertIn("incompatible path values", correction["instruction"])
        self.assertIn("TypeError: unsupported operand", correction["last_stderr"])

    def test_network_failure_requests_bounded_stdlib_harness(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "import socket\nprint('probe')"},
                "rationale": "bound network retry",
                "expected_signal": "connection state",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(goal="Probe an interactive TCP service without hanging."),
            state=RunState(objective="Solve."),
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "",
                    "stderr_preview": "ConnectionRefusedError: [Errno 61] Connection refused",
                    "returncode": 1,
                    "failure_kind": "connection_refused",
                    "failure_detail": "remote endpoint refused the connection",
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertIn("observed connection failure", correction["instruction"])
        self.assertIn("authorized scope", correction["instruction"])
        self.assertIn("ConnectionRefusedError", correction["last_stderr"])

    def test_protocol_parse_error_warns_about_non_newline_prompts(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "import socket\nprint('fixed parser')"},
                "rationale": "fix prompt parser",
                "expected_signal": "protocol transcript handled",
            }

        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=TodoItem(
                goal="Fix an interactive TCP solver that mis-parsed prompts."
            ),
            state=RunState(objective="Solve."),
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "quarters (25c): dimes (10c): nickels (5c): pennies (1c):",
                    "stderr_preview": "",
                    "returncode": 0,
                    "failure_kind": "parse_error",
                    "failure_detail": "script parsing logic rejected tool or service output",
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertIn("observed raw output", correction["instruction"])
        self.assertIn("quarters", correction["last_stdout"])

    def test_timeout_correction_warns_about_non_newline_prompts(self) -> None:
        instruction = script_correction_instruction("timeout")
        self.assertIn("last_traceback", instruction)
        self.assertIn("terminates within the tool timeout", instruction)
        self.assertNotIn("full recovery only on finalists", instruction)

    def test_binary_structure_error_correction_preserves_artifact_path(self) -> None:
        instruction = script_correction_instruction("binary_structure_error")
        self.assertIn("observed lengths", instruction)
        self.assertIn("bounds checks", instruction)

    def test_scope_violation_correction_constrains_script_paths(self) -> None:
        instruction = script_correction_instruction("scope_violation_blocked")
        self.assertIn("CTF_FILES_ROOT", instruction)
        self.assertIn("CTF_TEMP_DIR", instruction)
        self.assertIn("do not hard-code /tmp", instruction)

    def test_scratch_space_correction_uses_disposable_temp_dir(self) -> None:
        instruction = script_correction_instruction("scratch_space_exhausted")
        self.assertIn("provided writable locations", instruction)

    def test_same_todo_unbounded_failure_survives_local_no_candidate_step(self) -> None:
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "print('bounded')"},
                "rationale": "use bounded corrected value",
                "expected_signal": "no huge range",
            }

        task = TodoItem(goal="Decrypt data with corrected skip=34112.")
        state = RunState(objective="Solve.")
        state.evidence["evidence-unbounded"] = EvidenceRecord(
            evidence_id="evidence-unbounded",
            task_id=task.todo_id,
            capability="script.exec",
            tool_name="script_exec",
            mode="local_command",
            summary="script failed: range too large",
            extracted={
                "output_context": {
                    "failure_kind": "unbounded_loop_guard",
                    "failure_detail": "script attempted an oversized range",
                    "stdout": "Skip raw: 34112\nSkip after SWAP: 1082458112\n",
                    "stderr": "RuntimeError: range too large for script.exec: 1082458112 > 5000000",
                    "returncode": 1,
                }
            },
        )
        worker = _PromptWorker(
            llm_client=StaticLLMClient(respond), execution_plane=ExecutionPlane()
        )
        worker.choose_tool_use(
            task=task,
            state=state,
            allowed_capabilities=[ToolCapability.SCRIPT_EXEC],
            prior_steps=[
                {
                    "capability": "script.exec",
                    "stdout_preview": "diagnostic ran but no flag",
                    "stderr_preview": "",
                    "flag_candidates": [],
                    "returncode": 0,
                    "failure_kind": "no_candidate",
                }
            ],
        )
        correction = captured["snapshot"]["correction_context"]
        self.assertEqual(correction["failure_kind"], "unbounded_loop_guard")
        self.assertIn("1082458112", correction["last_stderr"])
        self.assertIn("terminates within the tool timeout", correction["instruction"])
        constraints = correction["execution_constraints"]
        self.assertIn(1082458112, constraints["do_not_iterate_values"])
        self.assertIn(
            {"label": "corrected_skip", "value": 34112, "source": "todo.goal"},
            constraints["bounded_counter_candidates"],
        )


if __name__ == "__main__":
    unittest.main()
