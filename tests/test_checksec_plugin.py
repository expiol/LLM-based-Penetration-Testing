from __future__ import annotations

import unittest

from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutputStatus,
)
from killchain_docker.tools.plugins.checksec import build_output


class ChecksecPluginTests(unittest.TestCase):
    def test_parses_table_output_from_stderr(self) -> None:
        request = ToolExecutionRequest(
            tool_name="checksec",
            timeout_s=120,
            metadata={"path": "/challenge/files/program"},
        )
        result = ToolExecutionResult(
            tool_name="checksec",
            mode=ExecutionMode.LOCAL_COMMAND,
            exit_code=0,
            stdout="",
            stderr=(
                "Warning: _curses.error: setupterm: could not find terminfo database\n"
                "[*] '/challenge/files/program'\n"
                "    Arch:       amd64-64-little\n"
                "    RELRO:      Partial RELRO\n"
                "    Stack:      Canary found\n"
                "    NX:         NX enabled\n"
                "    PIE:        No PIE (0x400000)\n"
            ),
        )

        output = build_output(request, result, ParsedToolOutput(summary="raw"))

        self.assertEqual(output.status, ToolOutputStatus.SUCCESS)
        self.assertEqual(output.output_context["relro"], "partial")
        self.assertTrue(output.output_context["canary"])
        self.assertTrue(output.output_context["nx"])
        self.assertFalse(output.output_context["pie"])
        self.assertIn("Canary", output.summary)


if __name__ == "__main__":
    unittest.main()
