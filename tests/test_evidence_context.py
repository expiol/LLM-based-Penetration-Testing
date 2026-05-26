from __future__ import annotations
import json
import unittest
from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.state.evidence_facts import EvidenceFactStore
from killchain_docker.state.recon_facts import ReconFactStore
from killchain_docker.state.domain import EvidenceRecord
from killchain_docker.state.run_state import RunState


class EvidenceContextTests(unittest.TestCase):
    def test_shell_output_keeps_key_lines_and_preview(self) -> None:
        state = RunState(objective="solve")
        EvidenceFactStore(state).evidence(
            EvidenceRecord(
                task_id="todo-shell",
                tool_name="shell_exec",
                mode="local_command",
                summary="shell: xxd flag.bin",
                result={
                    "exit_code": 0,
                    "stdout": "00000000: 53 54 46 55 aa bb cc dd  STFU....\nplain bytes\n",
                    "stderr": "",
                },
                extracted={"output_context": {"returncode": 0}},
            )
        )
        context = EvidenceContextBuilder(category="crypto").build(state)
        self.assertEqual(len(context), 1)
        rendered = json.dumps(context)
        self.assertIn("stdout_key_lines", rendered)
        self.assertIn("53 54 46 55", rendered)
        self.assertIn("stdout_preview", rendered)

    def test_binary_tool_result_stdout_is_kept_when_output_context_is_structured(
        self,
    ) -> None:
        state = RunState(objective="solve")
        EvidenceFactStore(state).evidence(
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

    def test_task_referenced_evidence_is_pinned_into_context(self) -> None:
        state = RunState(objective="solve")
        state.evidence["evidence-old"] = EvidenceRecord(
            evidence_id="evidence-old",
            task_id="todo-old",
            capability="curl",
            tool_name="curl",
            mode="local_command",
            summary="low score but referenced",
            extracted={
                "output_context": {
                    "stdout": "referenced secret transcript should survive filters"
                }
            },
        )
        for index in range(5):
            evidence_id = f"evidence-new-{index}"
            state.evidence[evidence_id] = EvidenceRecord(
                evidence_id=evidence_id,
                task_id=f"todo-new-{index}",
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="new script output",
                extracted={
                    "output_context": {
                        "returncode": 0,
                        "stdout": f"recent hex 0x{index} flag candidate",
                    }
                },
            )

        context = EvidenceContextBuilder(max_records=2).build(
            state,
            allowed_capabilities={"script.exec"},
            pinned_evidence_ids=["evidence-old"],
        )

        self.assertEqual(context[0]["evidence_id"], "evidence-old")
        self.assertEqual(context[0]["selection_reason"], "task_referenced")
        self.assertIn("referenced secret transcript", json.dumps(context))


if __name__ == "__main__":
    unittest.main()
