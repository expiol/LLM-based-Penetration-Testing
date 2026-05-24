from __future__ import annotations

import json
import unittest

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.state import EvidenceRecord, RunState


class EvidenceContextTests(unittest.TestCase):
    def test_shell_output_keeps_key_lines_and_preview(self) -> None:
        state = RunState(objective="solve")
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-shell",
                tool_name="shell_exec",
                mode="local_command",
                summary="shell: xxd flag.bin",
                result={"exit_code": 0, "stdout": "00000000: 53 54 46 55 aa bb cc dd  STFU....\nplain bytes\n", "stderr": ""},
                extracted={"output_context": {"returncode": 0}},
            )
        )

        context = EvidenceContextBuilder(category="crypto").build(state)

        self.assertEqual(len(context), 1)
        rendered = json.dumps(context)
        self.assertIn("stdout_key_lines", rendered)
        self.assertIn("53 54 46 55", rendered)
        self.assertIn("stdout_preview", rendered)

    def test_binary_tool_result_stdout_is_kept_when_output_context_is_structured(self) -> None:
        state = RunState(objective="solve")
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-objdump",
                tool_name="objdump",
                mode="local_command",
                summary="objdump stfu: 23 function(s)",
                result={
                    "exit_code": 0,
                    "stdout": "Disassembly of section .text:\n08048660 <.text>:\n xor eax, ebx\n shr eax, 1\n",
                    "stderr": "",
                },
                extracted={
                    "output_context": {
                        "path": "/tmp/stfu",
                        "function_count": 23,
                        "functions": [{"address": "08048660", "name": ".text"}],
                    }
                },
            )
        )

        context = EvidenceContextBuilder(category="rev").build(state)

        self.assertEqual(len(context), 1)
        rendered = json.dumps(context)
        self.assertIn("stdout_preview", rendered)
        self.assertIn("Disassembly of section", rendered)
        self.assertIn("08048660", rendered)
        self.assertIn("functions", rendered)


if __name__ == "__main__":
    unittest.main()
