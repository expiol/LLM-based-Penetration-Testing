"""Tests for tool metadata contracts — updated for 2-capability architecture."""

from __future__ import annotations

import unittest

from killchain_docker.state import RunState, TodoItem
from killchain_docker.tools import (
    ToolCapability,
    ToolExecutionError,
)
from killchain_docker.workers.tool_metadata import normalize_tool_metadata, tool_metadata_contract


class ToolMetadataContractTests(unittest.TestCase):
    def test_shell_exec_contract_requires_command(self) -> None:
        contract = tool_metadata_contract(ToolCapability.SHELL_EXEC)
        self.assertIn("command", contract["required"])

    def test_script_exec_contract_requires_script_code(self) -> None:
        contract = tool_metadata_contract(ToolCapability.SCRIPT_EXEC)
        self.assertIn("script_code", contract["required"])

    def test_shell_exec_normalization_requires_command(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SHELL_EXEC, todo, state, {})

    def test_shell_exec_normalization_passes_command(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SHELL_EXEC, todo, state,
            {"command": "nmap -sV 127.0.0.1"},
        )
        self.assertEqual(result["command"], "nmap -sV 127.0.0.1")

    def test_script_exec_normalization_requires_script_code(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        with self.assertRaises(ToolExecutionError):
            normalize_tool_metadata(ToolCapability.SCRIPT_EXEC, todo, state, {})

    def test_script_exec_normalization_passes_script_code(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state,
            {"script_code": "print('hello')"},
        )
        self.assertEqual(result["script_code"], "print('hello')")
        self.assertEqual(result["script_language"], "python")

    def test_script_exec_normalizes_language(self) -> None:
        state = RunState(objective="solve")
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state,
            {"script_code": "echo hi", "script_language": "shell"},
        )
        self.assertEqual(result["script_language"], "bash")

    def test_script_exec_passes_flag_format_from_challenge(self) -> None:
        state = RunState(
            objective="solve",
            metadata={"challenge": {"flag_format": "flag{...}"}},
        )
        todo = TodoItem(goal="test")
        result = normalize_tool_metadata(
            ToolCapability.SCRIPT_EXEC, todo, state,
            {"script_code": "print(1)"},
        )
        self.assertEqual(result["flag_format"], "flag{...}")


if __name__ == "__main__":
    unittest.main()
