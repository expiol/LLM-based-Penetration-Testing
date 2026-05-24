from __future__ import annotations

import unittest
from unittest.mock import patch

from killchain_docker.tools.core import (
    ExecutionMode,
    ToolExecutionRequest,
    ToolExecutionResult,
)
from killchain_docker.tools.plugins.nmap import NmapPlugin


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


if __name__ == "__main__":
    unittest.main()
