from __future__ import annotations

import unittest

from killchain_docker.state import RunState, TodoItem, WorkerResult
from killchain_docker.tools import (
    ExecutionMode,
    ExecutionPlane,
    ToolCapability,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolGateway,
    jsonl_signal_parser,
)


class _StaticPlugin:
    mode = ExecutionMode.SIMULATED

    def __init__(self) -> None:
        self.name = "http_path_probe"
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            stdout=(
                '{"type":"summary","text":"path probe ok"}\n'
                '{"type":"output_context","base_url":"http://example.test",'
                '"path_results":[{"url":"http://example.test/admin","status":200}],'
                '"flag_candidates":["flag{maybe}"]}\n'
            ),
        )


class _ScriptPlugin:
    mode = ExecutionMode.SIMULATED

    def __init__(self) -> None:
        self.name = "script_execution"
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            stdout=(
                '{"type":"summary","text":"script ok"}\n'
                '{"type":"output_context","returncode":0,'
                '"flag_candidates":["flag{script}"]}\n'
            ),
        )


class CapabilityGatewayTests(unittest.TestCase):
    def test_gateway_maps_capability_and_builds_typed_delta(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _StaticPlugin()
        plane.register_plugin(plugin)

        bundle = ToolGateway(plane).run(
            task_id="task-1",
            capability=ToolCapability.HTTP_PROBE_PATHS,
            metadata={"asset_id": "asset-1", "base_url": "http://example.test"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.capability, ToolCapability.HTTP_PROBE_PATHS.value)
        self.assertEqual(plugin.last_request.tool_name, "http_path_probe")
        self.assertEqual(bundle.evidence.capability, ToolCapability.HTTP_PROBE_PATHS.value)
        self.assertEqual(bundle.state_delta.routes[0].url, "http://example.test/admin")
        self.assertEqual(bundle.state_delta.routes[0].source, ToolCapability.HTTP_PROBE_PATHS.value)
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{maybe}")
        self.assertEqual(
            bundle.state_delta.flag_candidates[0].source,
            ToolCapability.HTTP_PROBE_PATHS.value,
        )

        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Probe paths"))
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
        self.assertEqual(len(state.routes), 1)
        self.assertEqual(len(state.flag_candidates), 1)

    def test_script_execute_maps_to_script_plugin(self) -> None:
        plane = ExecutionPlane()
        plane.register_parser("jsonl_signals", jsonl_signal_parser)
        plugin = _ScriptPlugin()
        plane.register_plugin(plugin)

        bundle = ToolGateway(plane).run(
            task_id="task-2",
            capability=ToolCapability.SCRIPT_EXECUTE,
            metadata={"script_code": "print('flag{script}')"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.tool_name, "script_execution")
        self.assertEqual(plugin.last_request.capability, "script.execute")
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{script}")
        self.assertEqual(bundle.state_delta.exploit_attempts[0].technique, "script.execute")


if __name__ == "__main__":
    unittest.main()
