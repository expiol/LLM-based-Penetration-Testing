from __future__ import annotations

import unittest
from unittest.mock import patch

from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins.nmap import NmapPlugin, build_output


class NmapPluginTests(unittest.TestCase):
    def test_default_scan_adds_bounded_timing_args(self) -> None:
        with patch("killchain_docker.tools.plugins.nmap._run") as run:
            run.return_value = ToolExecutionResult(
                tool_name="nmap",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

            NmapPlugin().execute(
                ToolExecutionRequest(
                    tool_name="nmap",
                    timeout_s=180,
                    metadata={
                        "target": "service.example",
                        "ports": "31337",
                        "scan_type": "-sV",
                    },
                )
            )

        argv = run.call_args.args[1]
        timeout_s = run.call_args.args[2]
        command = argv[-1]
        self.assertIn("--host-timeout 45s", command)
        self.assertIn("--max-retries 1", command)
        self.assertIn("-p 31337", command)
        self.assertEqual(timeout_s, 60)

    def test_explicit_timing_args_are_preserved(self) -> None:
        with patch("killchain_docker.tools.plugins.nmap._run") as run:
            run.return_value = ToolExecutionResult(
                tool_name="nmap",
                mode=ExecutionMode.LOCAL_COMMAND,
                exit_code=0,
                stdout="",
                stderr="",
            )

            NmapPlugin().execute(
                ToolExecutionRequest(
                    tool_name="nmap",
                    timeout_s=120,
                    metadata={
                        "target": "service.example",
                        "scan_type": "-sV --host-timeout 90s",
                        "extra_args": "--max-retries 3",
                    },
                )
            )

        command = run.call_args.args[1][-1]
        timeout_s = run.call_args.args[2]
        self.assertIn("--host-timeout 90s", command)
        self.assertIn("--max-retries 3", command)
        self.assertEqual(timeout_s, 120)

    def test_host_timeout_is_not_reported_as_zero_open_ports(self) -> None:
        request = ToolExecutionRequest(
            tool_name="nmap",
            timeout_s=120,
            metadata={
                "target": "service.example",
                "ports": "4242",
                "scan_type": "-sV",
            },
        )
        result = ToolExecutionResult(
            tool_name="nmap",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout=(
                "Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-25 11:25 UTC\n"
                "Nmap scan report for service.example (192.0.2.10)\n"
                "Host is up (0.00053s latency).\n"
                "Skipping host service.example (192.0.2.10) due to host timeout\n"
                "Nmap done: 1 IP address (1 host up) scanned in 49.34 seconds\n"
            ),
            stderr="",
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.status, ToolOutputStatus.FAILURE)
        self.assertIn("timed out", output.summary)
        self.assertEqual(output.output_context["failure_kind"], "scan_timeout")
        self.assertEqual(output.output_context["result_quality"], "scan_incomplete")
        self.assertEqual(output.output_context["requested_ports"], "4242")
        self.assertEqual(output.output_context["port_count"], 0)


if __name__ == "__main__":
    unittest.main()
