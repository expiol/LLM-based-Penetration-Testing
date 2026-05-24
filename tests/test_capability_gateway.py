"""Tests for the capability gateway with the new 2-plugin architecture."""

from __future__ import annotations

import sys
import shlex
import tempfile
import time
import unittest
from pathlib import Path

from killchain_docker.state import RunState, TodoItem, WorkerResult
from killchain_docker.tools import (
    ExecutionMode,
    ExecutionPlane,
    ParsedToolOutput,
    ToolCapability,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolGateway,
    ToolOutput,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins.shell import (
    ShellPlugin,
    build_output as shell_output_builder,
    http_client_non_http_url_block_reason,
    package_install_block_reason,
)
from killchain_docker.tools.plugins._base import _run
from killchain_docker.tools.plugins.script import build_output as script_output_builder
from killchain_docker.tools.plugins.script import ScriptPlugin
from killchain_docker.tools.plugins.foremost import build_output as foremost_output_builder
from killchain_docker.tools.plugins.tshark import build_output as tshark_output_builder
from killchain_docker.workers.protocols import PersonaSpec
from killchain_docker.workers.worker import Worker
from killchain_docker.llm import StaticLLMClient


class _StaticShellPlugin:
    mode = ExecutionMode.SIMULATED
    name = "shell_exec"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="flag{shell_test}\n",
        )


class _StaticScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="flag{script_test}\n",
        )


class _FailingShellPlugin:
    mode = ExecutionMode.SIMULATED
    name = "shell_exec"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=1,
            stdout="",
            stderr="deterministic tool failure",
        )


class _FailingScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=1,
            stdout="Skip after SWAP: 1082458112\n",
            stderr="RuntimeError: range too large for script.exec: 1082458112 > 5000000",
        )


class _InfrastructureScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=1,
            stdout="",
            stderr="Error response from daemon: No such container: abc123",
        )


class _NoCandidateScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="decrypted preview contained printable text but no valid flag\n",
        )


class _NearMissThenCandidateScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def __init__(self) -> None:
        self.calls = 0

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.calls += 1
        if self.calls == 1:
            ascii_art = "\n".join(
                [
                    "  _  __ _____ __   __   _____  ______  __  __  _____ ",
                    " | |/ /| ____|\\ \\ / /  |  ___||  ____||  \\/  || ____|",
                    " | ' / |  _|   \\ V /   | |_   | |_   | |\\/| ||  _|  ",
                    " | . \\ | |___   | |    |  _|  |  _|  | |  | || |___ ",
                    " |_|\\_\\|_____|  |_|    |_|    |_|    |_|  |_||_____|",
                ]
                * 6
            )
            return ToolExecutionResult(
                tool_name=self.name,
                mode=self.mode,
                exit_code=0,
                stdout=ascii_art,
            )
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="FLAG FOUND: flag{closure_ok}\n",
        )


class _NonzeroNormalizedSuccessPlugin:
    mode = ExecutionMode.SIMULATED
    name = "ltrace"

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=1,
            stdout="+++ exited (status 1) +++\n",
        )


def _normalized_success_output_builder(
    _request: ToolExecutionRequest,
    _result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    return ToolOutput(
        status=ToolOutputStatus.SUCCESS,
        summary="ltrace target: 0 call(s), 0 unique function(s)",
        output_text="+++ exited (status 1) +++",
        output_context={"total_calls": 0, "unique_functions": 0},
    )


class CapabilityGatewayTests(unittest.TestCase):
    def test_gateway_maps_shell_exec_capability(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticShellPlugin()
        plane.register(plugin, shell_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-1",
            capability=ToolCapability.SHELL_EXEC,
            metadata={"command": "echo flag{shell_test}"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.capability, ToolCapability.SHELL_EXEC.value)
        self.assertEqual(plugin.last_request.tool_name, "shell_exec")
        self.assertEqual(bundle.evidence.capability, ToolCapability.SHELL_EXEC.value)
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{shell_test}")

    def test_gateway_maps_script_exec_capability(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticScriptPlugin()
        plane.register(plugin, script_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-2",
            capability=ToolCapability.SCRIPT_EXEC,
            metadata={"script_code": "print('flag{script_test}')"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.tool_name, "script_exec")
        self.assertEqual(plugin.last_request.capability, "script.exec")
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{script_test}")

    def test_script_hint_uses_fixed_metadata_path(self) -> None:
        captured: dict[str, str] = {}

        def response(system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["system"] = system_prompt
            captured["user"] = user_prompt
            return {
                "capability": "script.exec",
                "metadata": {"script_code": "print('flag{script_test}')"},
                "rationale": "generate fixed script metadata",
            }

        plane = ExecutionPlane()
        plugin = _StaticScriptPlugin()
        plane.register(plugin, script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SCRIPT_EXEC,),
            ),
            llm_client=StaticLLMClient(response),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = TodoItem(
            goal="Build a bounded solver harness.",
            context={
                "capability_hint": "script.exec",
                "dispatch_intent": {"required_capability": "script.exec"},
            },
        )

        result = worker.run(todo, state)

        self.assertTrue(result.success)
        self.assertEqual(plugin.last_request.metadata["script_code"], "print('flag{script_test}')")
        self.assertIn("already selected the capability", captured["system"])
        self.assertIn('"fixed_capability": "script.exec"', captured["user"])
        self.assertNotIn("ONLY available capabilities", captured["system"])

    def test_tshark_empty_output_has_structured_signal(self) -> None:
        output = tshark_output_builder(
            ToolExecutionRequest(
                tool_name="tshark",
                metadata={"path": "/tmp/capture.pcap", "filter": "tcp"},
            ),
            ToolExecutionResult(
                tool_name="tshark",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            ),
            ParsedToolOutput(summary="raw"),
        )

        self.assertEqual(output.output_context["packet_count"], 0)
        self.assertEqual(output.output_context["failure_kind"], "empty_result")
        self.assertEqual(output.output_context["result_quality"], "empty_result")

    def test_state_delta_applies_to_run_state(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticShellPlugin()
        plane.register(plugin, shell_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-3",
            capability=ToolCapability.SHELL_EXEC,
            metadata={"command": "grep -r flag /tmp"},
        )

        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Find flags"))
        state.apply_worker_result(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="recon-worker",
                success=True,
                summary=bundle.parsed.summary,
                state_delta=bundle.state_delta,
                evidence_updates=[bundle.evidence],
            )
        )
        self.assertEqual(len(state.flag_candidates), 1)

    def test_worker_tool_failure_is_terminal_for_same_todo(self) -> None:
        plane = ExecutionPlane()
        plane.register(_FailingShellPlugin(), shell_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SHELL_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "shell.exec",
                    "metadata": {"command": "false"},
                    "rationale": "simulate deterministic failure",
                }
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = TodoItem(goal="Run a deterministic failing diagnostic")

        result = worker.run(todo, state)

        self.assertFalse(result.success)
        self.assertFalse(result.retryable)

    def test_worker_infrastructure_failure_is_retryable_not_partial(self) -> None:
        plane = ExecutionPlane()
        plane.register(_InfrastructureScriptPlugin(), script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SCRIPT_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "print('work')"},
                    "rationale": "simulate runtime infrastructure failure",
                }
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Decrypt the ciphertext and recover the flag."))

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertFalse(result.success)
        self.assertFalse(result.partial)
        self.assertTrue(result.retryable)
        self.assertEqual(result.result_quality, "infrastructure_error")
        self.assertEqual(state.todos[0].status.value, "pending")

    def test_flag_recovery_script_failure_becomes_partial_evidence(self) -> None:
        plane = ExecutionPlane()
        plane.register(_FailingScriptPlugin(), script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SCRIPT_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "for _ in range(10**9): pass"},
                    "rationale": "simulate failed generated solver",
                },
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "for _ in range(10**9): pass"},
                    "rationale": "simulate corrected solver still failing",
                },
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Decrypt the ciphertext and recover the flag."))

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertFalse(result.success)
        self.assertTrue(result.partial)
        self.assertFalse(result.retryable)
        self.assertEqual(state.todos[0].status.value, "partial")
        self.assertIn("oversized range", state.todos[0].error or "")

    def test_worker_hands_metadata_validation_error_back_to_planner(self) -> None:
        plane = ExecutionPlane()
        shell_plugin = _StaticShellPlugin()
        script_plugin = _StaticScriptPlugin()
        plane.register(shell_plugin, shell_output_builder)
        plane.register(script_plugin, script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(
                    ToolCapability.SHELL_EXEC,
                    ToolCapability.SCRIPT_EXEC,
                ),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "shell.exec",
                    "metadata": {
                        "command": "python3 -c \"for i in range(3): print(i)\"",
                    },
                    "rationale": "bad one-line Python",
                },
                {
                    "capability": "script.exec",
                    "metadata": {
                        "script_code": (
                            "from pathlib import Path\n"
                            "Path('/tmp/recovered.txt').write_text('x')\n"
                            "print('done')\n"
                        ),
                    },
                    "rationale": "bad scratch path",
                },
                {
                    "capability": "script.exec",
                    "metadata": {
                        "script_code": (
                            "import os\n"
                            "from pathlib import Path\n"
                            "scratch = Path(os.environ.get('CTF_TEMP_DIR', '.'))\n"
                            "scratch.joinpath('recovered.txt').write_text('x')\n"
                            "print('flag{script_test}')\n"
                        ),
                    },
                    "rationale": "use disposable scratch path",
                },
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(
            TodoItem(
                goal="Decode recovered artifact and recover the flag.",
                success_criteria=["Print the flag candidate."],
            )
        )

        result = worker.run(todo, state)

        self.assertFalse(result.success)
        self.assertTrue(result.partial)
        self.assertEqual(result.result_quality, "shell_python_complexity")
        self.assertEqual(result.output_context["agent_handoff"]["target"], "planner")
        self.assertIsNone(shell_plugin.last_request)
        self.assertIsNone(script_plugin.last_request)

    def test_partial_flag_recovery_does_not_persist_speculative_memory(self) -> None:
        plane = ExecutionPlane()
        plane.register(_NoCandidateScriptPlugin(), script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SCRIPT_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "print('no flag')"},
                    "rationale": "simulate a no-candidate solver",
                    "memory_updates": {
                        "decryption_confirmed": "algorithm variant is confirmed",
                    },
                },
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "print('still no flag')"},
                    "rationale": "simulate a corrected no-candidate solver",
                    "memory_updates": {
                        "candidate_confirmed": "flag candidate is confirmed",
                    },
                },
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Decrypt the ciphertext and recover the flag."))

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertTrue(result.partial)
        self.assertEqual(result.memory_updates, {})
        self.assertEqual(state.working_memory, {})

    def test_artifact_closure_task_hands_near_miss_back_to_planner(self) -> None:
        plugin = _NearMissThenCandidateScriptPlugin()
        plane = ExecutionPlane()
        plane.register(plugin, script_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SCRIPT_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "print('near miss image text')"},
                    "rationale": "recover embedded image text",
                },
                {
                    "capability": "script.exec",
                    "metadata": {"script_code": "print('final candidate')"},
                    "rationale": "extract candidate from near miss",
                },
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(
            TodoItem(
                goal="Extract embedded PNG and recover hidden key from image.",
                success_criteria=["Recover a candidate from the hidden image content."],
            )
        )

        result = worker.run(todo, state)

        self.assertEqual(plugin.calls, 1)
        self.assertTrue(result.partial)
        self.assertEqual(result.result_quality, "near_miss")
        self.assertEqual(result.output_context["agent_handoff"]["target"], "planner")
        self.assertEqual(result.state_delta.flag_candidates, [])

    def test_successful_worker_can_persist_grounded_memory(self) -> None:
        plane = ExecutionPlane()
        plane.register(_StaticShellPlugin(), shell_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.SHELL_EXEC,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "shell.exec",
                    "metadata": {"command": "printf ok"},
                    "rationale": "simulate grounded analysis",
                    "memory_updates": {"format": "ELF binary with a helper data file"},
                },
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Inspect challenge artifacts."))

        result = worker.run(todo, state)
        state.apply_worker_result(result)

        self.assertFalse(result.partial)
        self.assertEqual(state.working_memory["format"], "ELF binary with a helper data file")

    def test_worker_respects_normalized_tool_status_for_nonzero_trace_exit(self) -> None:
        plane = ExecutionPlane()
        plane.register(_NonzeroNormalizedSuccessPlugin(), _normalized_success_output_builder)
        worker = Worker(
            persona=PersonaSpec(
                name="artifact-worker",
                allowed_capabilities=(ToolCapability.LTRACE,),
            ),
            llm_client=StaticLLMClient([
                {
                    "capability": "ltrace",
                    "metadata": {"path": "/bin/false"},
                    "rationale": "trace a binary that exits nonzero",
                }
            ]),
            tool_gateway=ToolGateway(plane),
        )
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = TodoItem(goal="Run dynamic trace to observe runtime behavior")

        result = worker.run(todo, state)

        self.assertTrue(result.success)
        self.assertIn("0 call(s)", result.summary)

    def test_script_plugin_writes_code_via_stdin_not_shell_argv(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    capability=ToolCapability.SCRIPT_EXEC.value,
                    tool_name="script_exec",
                    metadata={
                        "script_code": "print(\"flag{stdin_script_ok}\")\nprint(\"quote:' and dollar:$HOME\")",
                        "script_language": "python",
                        "files_root": tmp,
                    },
                    timeout_s=20,
                )
            )

        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("flag{stdin_script_ok}", result.stdout)
        self.assertIn("dollar:$HOME", result.stdout)

    def test_script_plugin_runs_original_temp_file_as_main(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            result = plugin.execute(
                ToolExecutionRequest(
                    capability=ToolCapability.SCRIPT_EXEC.value,
                    tool_name="script_exec",
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": (
                            "import pathlib, sys\n"
                            "print('__name__=' + __name__)\n"
                            "print('argv0=' + pathlib.Path(sys.argv[0]).name)\n"
                            "print('file=' + pathlib.Path(__file__).name)\n"
                        ),
                    },
                    timeout_s=20,
                )
            )

        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("__name__=__main__", result.stdout)
        self.assertIn("argv0=_script_", result.stdout)
        self.assertIn("file=_script_", result.stdout)

    def test_script_plugin_uses_disposable_files_root_copy(self) -> None:
        plugin = ScriptPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.txt"
            target.write_text("original", encoding="utf-8")

            result = plugin.execute(
                ToolExecutionRequest(
                    capability=ToolCapability.SCRIPT_EXEC.value,
                    tool_name="script_exec",
                    metadata={
                        "script_language": "python",
                        "files_root": tmp,
                        "script_code": (
                            "from pathlib import Path\n"
                            "Path('artifact.txt').write_text('mutated')\n"
                            "Path('derived.txt').write_text('scratch')\n"
                            "print(Path('artifact.txt').read_text())\n"
                        ),
                    },
                    timeout_s=20,
                )
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertIn("mutated", result.stdout)
            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertFalse((Path(tmp) / "derived.txt").exists())


class ForensicsToolOutputTests(unittest.TestCase):
    def test_foremost_registers_durable_carved_file_paths(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.FOREMOST.value,
            tool_name="foremost",
            metadata={"path": "/home/ctfplayer/ctf_files/out.img"},
            timeout_s=30,
        )
        stdout = "\n".join(
            [
                "Foremost started at Fri May 23 00:00:00 2026",
                "__KILLCHAIN_FOREMOST_FILES__",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/foremost_out/gif/00000000.gif\t1234",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/foremost_out/jpg/00000001.jpg\t4567",
                "__KILLCHAIN_FOREMOST_AUDIT__",
                "/home/ctfplayer/ctf_files/.autopentest_artifacts/foremost_out/audit.txt",
                "0: foundat=ppt/media/image0.gifUT 0 0",
            ]
        )
        result = ToolExecutionResult(
            tool_name="foremost",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

        output = foremost_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["carved_count"], 2)
        self.assertTrue(output.output_context["carved_files_durable"])
        self.assertEqual(output.output_context["type_counts"], {"gif": 1, "jpg": 1})
        self.assertNotIn("foundat=", "\n".join(output.output_context["carved_files"]))
        self.assertEqual(len(output.artifacts), 2)
        self.assertEqual(
            output.artifacts[0].path,
            "/home/ctfplayer/ctf_files/.autopentest_artifacts/foremost_out/gif/00000000.gif",
        )
        self.assertEqual(output.artifacts[0].kind, "foremost_gif")
        self.assertEqual(output.artifacts[0].size, 1234)


class ShellPluginGuardrailTests(unittest.TestCase):
    def test_blocks_system_package_install_before_subprocess(self) -> None:
        plugin = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"])
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "apt-get update && apt-get install -y qemu-user-static"},
            timeout_s=5,
        )

        result = plugin.execute(request)
        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("package installation", result.stderr)
        self.assertEqual(output.output_context["failure_kind"], "package_install_blocked")

    def test_classifies_missing_shell_tool_from_captured_stderr(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "fdisk -l out.img 2>&1 && mmls out.img"},
            timeout_s=5,
        )
        result = ToolExecutionResult(
            tool_name="shell_exec",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=127,
            stdout="bash: line 1: fdisk: command not found\n",
            stderr="",
        )

        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["failure_kind"], "missing_tool")
        self.assertIn("fdisk", str(output.output_context["failure_detail"]))

    def test_classifies_docker_container_error_as_infrastructure(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "cat /home/ctfplayer/ctf_files/out.img"},
            timeout_s=5,
        )
        result = ToolExecutionResult(
            tool_name="shell_exec",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=1,
            stdout="",
            stderr="Error response from daemon: No such container: abc123\n",
        )

        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["failure_kind"], "infrastructure_error")
        self.assertIn("runtime container", str(output.output_context["failure_detail"]))

    def test_classifies_stopped_docker_container_as_infrastructure(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "python3 solve.py"},
            timeout_s=5,
        )
        result = ToolExecutionResult(
            tool_name="shell_exec",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=1,
            stdout="",
            stderr=(
                "Error response from daemon: container "
                "268b12d34abc is not running\n"
            ),
        )

        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.output_context["failure_kind"], "infrastructure_error")
        self.assertIn("runtime container", str(output.output_context["failure_detail"]))

    def test_blocks_loopback_target_when_scope_is_remote(self) -> None:
        plugin = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"])
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={
                "command": "curl -sS http://localhost:8000/.bashrc",
                "authorized_scope": ["tcp://remote.example:8000"],
            },
            timeout_s=5,
        )

        result = plugin.execute(request)
        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("outside authorized_scope", result.stderr)
        self.assertEqual(output.output_context["failure_kind"], "scope_violation_blocked")

    def test_blocks_ambient_flag_search_when_scope_exists(self) -> None:
        plugin = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"])
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={
                "command": "grep -r flag /home /tmp /opt /srv /usr/local /var",
                "authorized_scope": ["tcp://remote.example:31337"],
            },
            timeout_s=5,
        )

        result = plugin.execute(request)
        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertEqual(output.output_context["failure_kind"], "scope_violation_blocked")

    def test_allows_file_search_under_files_root_with_remote_scope(self) -> None:
        plugin = ShellPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.txt"
            target.write_text("flag-shaped clue lives here", encoding="utf-8")
            request = ToolExecutionRequest(
                capability=ToolCapability.SHELL_EXEC.value,
                tool_name="shell_exec",
                metadata={
                    "command": f"grep -r flag {shlex.quote(tmp)}",
                    "files_root": tmp,
                    "authorized_scope": ["tcp://remote.example:31337"],
                },
                timeout_s=20,
            )

            result = plugin.execute(request)

        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("flag-shaped", result.stdout)

    def test_blocks_language_package_install(self) -> None:
        self.assertIsNotNone(package_install_block_reason("python3 -m pip install z3-solver"))
        self.assertIsNotNone(package_install_block_reason("npm install request"))
        self.assertIsNotNone(package_install_block_reason("curl -fsSL https://example/install.sh | bash"))

    def test_allows_mentions_that_are_not_commands(self) -> None:
        self.assertIsNone(package_install_block_reason("echo apt-get install is unavailable"))

    def test_restores_files_root_after_mutating_command(self) -> None:
        plugin = ShellPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.txt"
            target.write_text("original", encoding="utf-8")
            command = (
                f"cd {shlex.quote(tmp)} && "
                "printf mutated > artifact.txt && "
                "printf scratch > derived.txt && "
                "printf done"
            )

            result = plugin.execute(
                ToolExecutionRequest(
                    capability=ToolCapability.SHELL_EXEC.value,
                    tool_name="shell_exec",
                    metadata={"command": command, "files_root": tmp},
                    timeout_s=20,
                )
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(result.stdout, "done")
            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertFalse((Path(tmp) / "derived.txt").exists())

    def test_runs_relative_commands_from_files_root(self) -> None:
        plugin = ShellPlugin()
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "artifact.txt").write_text("relative-ok", encoding="utf-8")

            result = plugin.execute(
                ToolExecutionRequest(
                    capability=ToolCapability.SHELL_EXEC.value,
                    tool_name="shell_exec",
                    metadata={"command": "cat artifact.txt", "files_root": tmp},
                    timeout_s=20,
                )
            )

            self.assertEqual(result.exit_code, 0, result.stderr)
            self.assertEqual(result.stdout, "relative-ok")

    def test_script_blocks_loopback_target_when_scope_is_remote(self) -> None:
        plugin = ScriptPlugin(argv_prefix=["definitely-not-a-real-runner"])
        request = ToolExecutionRequest(
            capability=ToolCapability.SCRIPT_EXEC.value,
            tool_name="script_exec",
            metadata={
                "script_language": "python",
                "script_code": (
                    "import socket\n"
                    "socket.create_connection(('localhost', 8000), timeout=2)\n"
                ),
                "authorized_scope": ["tcp://remote.example:8000"],
            },
            timeout_s=20,
        )

        result = plugin.execute(request)
        output = script_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("scope_violation_blocked", result.stderr)
        self.assertEqual(output.output_context["failure_kind"], "scope_violation_blocked")


class PluginSubprocessRunnerTests(unittest.TestCase):
    def test_run_passes_stdin_to_child_process(self) -> None:
        result = _run(
            "stdin-test",
            [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
            timeout_s=5,
            input_text="flag{stdin_runner_ok}",
        )

        self.assertEqual(result.exit_code, 0, result.stderr)
        self.assertIn("flag{stdin_runner_ok}", result.stdout)

    def test_run_bounds_stdout_and_stderr_capture(self) -> None:
        result = _run(
            "capture-bound-test",
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "sys.stdout.write('A' * 1500 + 'STDOUT_TAIL'); "
                    "sys.stderr.write('B' * 1500 + 'STDERR_TAIL')"
                ),
            ],
            timeout_s=5,
            max_output_bytes=200,
        )

        self.assertEqual(result.exit_code, 0)
        self.assertIn("output truncated", result.stdout)
        self.assertIn("output truncated", result.stderr)
        self.assertIn("STDOUT_TAIL", result.stdout)
        self.assertIn("STDERR_TAIL", result.stderr)
        self.assertLess(len(result.stdout), 400)
        self.assertLess(len(result.stderr), 400)

    def test_run_reports_timeout(self) -> None:
        result = _run(
            "timeout-test",
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout_s=1,
        )

        self.assertEqual(result.exit_code, -1)
        self.assertIn("[timeout after 1s]", result.stderr)

    def test_run_timeout_kills_child_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "child_survived.txt"
            child_code = (
                "import pathlib, sys, time; "
                "time.sleep(2); "
                "pathlib.Path(sys.argv[1]).write_text('survived')"
            )
            parent_code = (
                "import subprocess, sys, time; "
                f"subprocess.Popen([sys.executable, '-c', {child_code!r}, {str(marker)!r}]); "
                "time.sleep(30)"
            )

            result = _run(
                "timeout-group-test",
                [sys.executable, "-c", parent_code],
                timeout_s=1,
            )
            time.sleep(2.5)

            self.assertEqual(result.exit_code, -1)
            self.assertFalse(marker.exists())


class _StaticCurlPlugin:
    """Simulated curl plugin that captures requests and returns canned HTTP response."""

    mode = ExecutionMode.SIMULATED
    name = "curl"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None
        self._sessions: dict[str, str] = {}

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        session_id = str(request.metadata.get("session_id") or "")
        cookie_header = ""
        if session_id:
            cookie_header = "Set-Cookie: session=abc123; Path=/\r\n"
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                f"HTTP/1.1 200 OK\r\n"
                f"Server: nginx/1.18\r\n"
                f"Content-Type: text/html\r\n"
                f"{cookie_header}"
                f"\r\n"
                f"<html><body>flag{{curl_session_test}}</body></html>\n"
            ),
        )


class CurlSessionTests(unittest.TestCase):
    """Tests for curl plugin session persistence and rich output parsing."""

    def test_curl_basic_request_emits_endpoint_and_route(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-1",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.tool_name, "curl")
        self.assertEqual(bundle.tool_output.status.value, "success")
        # Flag extracted from body
        self.assertTrue(any(
            fc.value == "flag{curl_session_test}"
            for fc in bundle.tool_output.flag_candidates
        ))
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        self.assertEqual(bundle.tool_output.endpoints[0].url, "http://target:8080")
        self.assertEqual(bundle.tool_output.endpoints[0].hostname, "target")
        self.assertEqual(bundle.tool_output.endpoints[0].status_code, 200)
        # Route emitted
        self.assertEqual(len(bundle.tool_output.routes), 1)
        self.assertEqual(bundle.tool_output.routes[0].url, "http://target:8080/login")
        self.assertEqual(bundle.tool_output.routes[0].path, "/login")
        self.assertEqual(bundle.tool_output.routes[0].method, "GET")
        # No session emitted (no session_id in metadata)
        self.assertEqual(len(bundle.tool_output.sessions), 0)

    def test_curl_session_id_emits_session_with_cookies(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-2",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login", "session_id": "web-recon"},
        )

        # Session emitted with cookie data
        self.assertEqual(len(bundle.tool_output.sessions), 1)
        sess = bundle.tool_output.sessions[0]
        self.assertEqual(sess.session_type, "http_cookie")
        self.assertEqual(sess.status, "active")
        self.assertEqual(sess.metadata["session_id"], "web-recon")
        self.assertIn("session=abc123", sess.metadata["cookies"][0])
        # Summary mentions session
        self.assertIn("[session:web-recon]", bundle.tool_output.summary)
        # output_context has cookies
        self.assertIn("set_cookies", bundle.tool_output.output_context)

    def test_curl_output_context_fields(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-3",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/api/data", "method": "POST"},
        )

        ctx = bundle.tool_output.output_context
        self.assertEqual(ctx["url"], "http://target:8080/api/data")
        self.assertEqual(ctx["method"], "POST")
        self.assertEqual(ctx["http_status"], 200)
        self.assertEqual(ctx["server"], "nginx/1.18")
        self.assertEqual(ctx["content_type"], "text/html")
        self.assertIn("POST", bundle.tool_output.summary)

    def test_curl_blocks_non_http_scheme_before_subprocess(self) -> None:
        from killchain_docker.tools.plugins.curl import (
            CurlPlugin,
            build_output as curl_output_builder,
        )

        request = ToolExecutionRequest(
            capability=ToolCapability.CURL.value,
            tool_name="curl",
            metadata={"url": "tcp://target:31337"},
            timeout_s=5,
        )
        result = CurlPlugin(argv_prefix=["definitely-not-a-real-runner"]).execute(request)
        output = curl_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("HTTP/HTTPS", result.stderr)
        self.assertEqual(output.output_context["failure_kind"], "non_http_url_blocked")

    def test_shell_blocks_non_http_curl_before_subprocess(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={
                "command": (
                    "curl -v --connect-timeout 10 --max-time 15 "
                    "tcp://target:31337 2>&1 || echo CURL_FAILED"
                ),
                "authorized_scope": ["tcp://target:31337"],
            },
            timeout_s=5,
        )

        result = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"]).execute(request)
        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("non-HTTP URL", result.stderr)
        self.assertEqual(output.output_context["failure_kind"], "non_http_url_blocked")

    def test_shell_http_client_guard_allows_http_urls(self) -> None:
        self.assertIsNone(
            http_client_non_http_url_block_reason("curl -sS http://target:8080/health")
        )

    def test_shell_blocks_stderr_suppression_before_subprocess(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "mmls out.img 2>/dev/null && fls out.img"},
            timeout_s=5,
        )

        result = ShellPlugin(argv_prefix=["definitely-not-a-real-runner"]).execute(request)
        output = shell_output_builder(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(result.exit_code, 126)
        self.assertIn("suppressed stderr", result.stderr)
        self.assertEqual(
            output.output_context["failure_kind"],
            "stderr_suppression_blocked",
        )

    def test_shell_guard_allows_stderr_to_stdout_redirect(self) -> None:
        request = ToolExecutionRequest(
            capability=ToolCapability.SHELL_EXEC.value,
            tool_name="shell_exec",
            metadata={"command": "printf err 2>&1"},
            timeout_s=5,
        )

        result = ShellPlugin(argv_prefix=["sh", "-c", "exit 0", "ignored"]).execute(request)

        self.assertNotEqual(result.exit_code, 126)

    def test_curl_auth_emits_credential_on_success(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-4",
            capability=ToolCapability.CURL,
            metadata={
                "url": "http://target:8080/admin",
                "auth": "admin:secret123",
            },
        )

        self.assertEqual(len(bundle.tool_output.credentials), 1)
        cred = bundle.tool_output.credentials[0]
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.credential_type, "http_basic")
        # Secret is masked in secret_ref
        self.assertIn("***", cred.secret_ref)
        self.assertNotIn("secret123", cred.secret_ref)

    def test_curl_session_state_delta_applies_to_run_state(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-5",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login", "session_id": "sess-1"},
        )

        state = RunState(objective="Solve web challenge.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Login to target"))
        state.apply_worker_result(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="web-worker",
                success=True,
                summary=bundle.parsed.summary,
                state_delta=bundle.state_delta,
                evidence_updates=[bundle.evidence],
            )
        )
        self.assertEqual(len(state.flag_candidates), 1)


class _StaticSqlmapPlugin:
    """Simulated sqlmap plugin returning canned injection results."""

    mode = ExecutionMode.SIMULATED
    name = "sqlmap"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                "[INFO] testing 'AND boolean-based blind'\n"
                "[INFO] GET parameter 'id' is vulnerable\n"
                "Parameter: id (GET)\n"
                "    Type: boolean-based blind\n"
                "    Type: UNION query\n"
                "sqlmap identified the following injection point(s):\n"
                "back-end DBMS: MySQL >= 5.0\n"
                "available databases [2]:\n"
                "[*] information_schema\n"
                "[*] ctf_db\n"
                "flag{sqli_found_1234}\n"
            ),
        )


class _StaticNiktoPlugin:
    """Simulated nikto plugin returning canned scan results."""

    mode = ExecutionMode.SIMULATED
    name = "nikto"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                "+ Target IP: 10.0.0.1\n"
                "+ Server: Apache/2.4.41\n"
                "+ /admin/: Directory listing found.\n"
                "+ OSVDB-3092: /phpinfo.php: phpinfo() information disclosure\n"
                "+ /shell.php: Possible backdoor found (remote code execution)\n"
                "+ /login.php: Default credential page\n"
                "+ Start Time: 2026-05-17\n"
            ),
        )


class SqlmapSessionTests(unittest.TestCase):
    """Tests for sqlmap plugin with session support and richer output."""

    def test_sqlmap_detects_injection_and_emits_findings(self) -> None:
        from killchain_docker.tools.plugins.sqlmap import build_output as sqlmap_builder

        plane = ExecutionPlane()
        plugin = _StaticSqlmapPlugin()
        plane.register(plugin, sqlmap_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-sqlmap-1",
            capability=ToolCapability.SQLMAP,
            metadata={"url": "http://target:8080/page?id=1"},
        )

        self.assertEqual(bundle.tool_output.status.value, "success")
        self.assertIn("INJECTABLE", bundle.tool_output.summary)
        self.assertIn("MySQL", bundle.tool_output.summary)
        # Findings emitted
        self.assertTrue(len(bundle.tool_output.findings) >= 1)
        self.assertEqual(bundle.tool_output.findings[0].severity, "critical")
        # Vulnerabilities for each parameter
        self.assertTrue(len(bundle.tool_output.vulnerabilities) >= 1)
        self.assertIn("id", bundle.tool_output.vulnerabilities[0].title)
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        self.assertEqual(bundle.tool_output.endpoints[0].hostname, "target")
        # output_context has detailed info
        ctx = bundle.tool_output.output_context
        self.assertTrue(ctx["injectable"])
        self.assertEqual(ctx["dbms"], "MySQL >= 5.0")
        self.assertIn("id", ctx["vulnerable_params"])
        self.assertIn("ctf_db", ctx["databases"])
        # Flag extracted
        self.assertTrue(any(
            fc.value == "flag{sqli_found_1234}"
            for fc in bundle.tool_output.flag_candidates
        ))

    def test_sqlmap_session_id_in_summary(self) -> None:
        from killchain_docker.tools.plugins.sqlmap import build_output as sqlmap_builder

        plane = ExecutionPlane()
        plugin = _StaticSqlmapPlugin()
        plane.register(plugin, sqlmap_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-sqlmap-2",
            capability=ToolCapability.SQLMAP,
            metadata={"url": "http://target/page?id=1", "session_id": "auth-sess"},
        )

        self.assertIn("[session:auth-sess]", bundle.tool_output.summary)
        self.assertEqual(bundle.tool_output.output_context["session_id"], "auth-sess")


class NiktoSessionTests(unittest.TestCase):
    """Tests for nikto plugin with session support and richer output."""

    def test_nikto_parses_findings_with_severity(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-1",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080"},
        )

        self.assertEqual(bundle.tool_output.status.value, "success")
        # Vulnerabilities emitted with severity classification
        vulns = bundle.tool_output.vulnerabilities
        self.assertTrue(len(vulns) >= 3)
        # shell.php should be high severity (backdoor / RCE)
        shell_vulns = [v for v in vulns if "shell" in v.title.lower() or "backdoor" in v.title.lower()]
        self.assertTrue(len(shell_vulns) >= 1)
        self.assertEqual(shell_vulns[0].severity, "high")
        # phpinfo should be medium severity (information disclosure)
        phpinfo_vulns = [v for v in vulns if "phpinfo" in v.title.lower()]
        self.assertTrue(len(phpinfo_vulns) >= 1)
        self.assertEqual(phpinfo_vulns[0].severity, "medium")
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        ep = bundle.tool_output.endpoints[0]
        self.assertEqual(ep.hostname, "target")
        self.assertTrue(ep.metadata.get("nikto_scanned"))
        # output_context has server info and severity counts
        ctx = bundle.tool_output.output_context
        self.assertEqual(ctx["server"], "Apache/2.4.41")
        self.assertEqual(ctx["target_ip"], "10.0.0.1")
        self.assertTrue(ctx["severity_counts"]["high"] >= 1)
        self.assertTrue(ctx["severity_counts"]["medium"] >= 1)

    def test_nikto_session_id_in_summary(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-2",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080", "session_id": "web-scan"},
        )

        self.assertIn("[session:web-scan]", bundle.tool_output.summary)
        self.assertEqual(bundle.tool_output.output_context["session_id"], "web-scan")

    def test_nikto_summary_includes_server(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-3",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080"},
        )

        self.assertIn("Apache/2.4.41", bundle.tool_output.summary)
        self.assertIn("finding(s)", bundle.tool_output.summary)


if __name__ == "__main__":
    unittest.main()
