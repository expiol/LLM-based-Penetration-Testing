"""Tests for the binary disassembly agent path + solver evidence pickup."""

from __future__ import annotations

import unittest

from killchain_docker.agents.artifact import BinaryTriageAgent
from killchain_docker.agents.solver import SolverEvidenceComposer
from killchain_docker.state import GlobalState, Task
from killchain_docker.state.models import EvidenceRecord
from killchain_docker.state.task_factory import (
    build_binary_disassembly_task,
    build_binary_run_task,
    build_binary_triage_task,
)


def _state(category: str = "crypto", files: tuple[str, ...] = ("stfu", "flag.stfu")) -> GlobalState:
    return GlobalState(
        objective="Solve test challenge.",
        authorized_scope=[],
        metadata={
            "challenge": {
                "name": "test",
                "category": category,
                "flag_format": "flag{...}",
                "files": list(files),
            },
        },
    )


def _disassembly_evidence(task_id: str, *, binary_name: str = "stfu") -> EvidenceRecord:
    """Return a fake binary_disassembly tool record for solver evidence tests."""
    return EvidenceRecord(
        task_id=task_id,
        tool_name="binary_disassembly",
        mode="cli",
        summary=f"Binary disassembly completed for 1 file(s).",
        request={"tool": "binary_disassembly"},
        result={},
        extracted={
            "output_context": {
                "files_root": "/home/ctfplayer/ctf_files",
                "inspected_binaries": [binary_name],
                "disassembly": {
                    binary_name: {
                        "file_type": "ELF 32-bit LSB executable",
                        "function_count_total": 14,
                        "function_count_kept": 3,
                        "symbol_table_present": True,
                        "functions": [
                            {
                                "name": "main",
                                "size_lines": 12,
                                "xref_strings": ["Supplied tap values out of range"],
                                "disassembly": "  mov eax, edi\n  call lfsr_step",
                            },
                        ],
                        "rodata": [
                            {
                                "address": "0x40c0",
                                "value": "Supplied tap values out of range",
                            },
                        ],
                    },
                },
            },
        },
    )


class BinaryTriageAgentDispatchTests(unittest.TestCase):
    """The agent owns three task types — verify it claims all correctly."""

    def test_supports_triage_disassembly_and_run(self):
        agent = BinaryTriageAgent()
        for ttype in (
            "artifact.binary_triage",
            "artifact.binary_disassembly",
            "artifact.binary_run",
        ):
            task = Task(
                title="t", description="d",
                task_type=ttype,
                input_context={
                    "files_root": "/home/ctfplayer/ctf_files",
                    "binary_files": ["stfu"],
                },
            )
            self.assertTrue(agent.supports(task), f"{ttype} should be supported")

    def test_supports_deep_review_only_for_binary_kind(self):
        agent = BinaryTriageAgent()
        binary_task = Task(
            title="t", description="d",
            task_type="artifact.deep_review",
            input_context={"analysis_kind": "binary", "binary_files": ["x"]},
        )
        archive_task = Task(
            title="t", description="d",
            task_type="artifact.deep_review",
            input_context={"analysis_kind": "archive", "archive_files": ["x"]},
        )
        self.assertTrue(agent.supports(binary_task))
        self.assertFalse(agent.supports(archive_task))

    def test_can_route_requires_binary_files(self):
        agent = BinaryTriageAgent()
        task_missing = Task(
            title="t", description="d",
            task_type="artifact.binary_disassembly",
            input_context={"files_root": "/home/ctfplayer/ctf_files"},
        )
        ok, reason = agent.can_route_task(task_missing, _state())
        self.assertFalse(ok)
        self.assertIn("binary_files", reason or "")


class BinaryTriageFollowupTests(unittest.TestCase):
    """After a triage with no flag in a rev/pwn/crypto challenge, the agent
    must auto-queue a disassembly follow-up via ``new_tasks``."""

    def _build_triage_report_via_post_process(
        self, *, category: str, flag_candidates: list[str],
    ):
        from killchain_docker.state import WorkerReport

        agent = BinaryTriageAgent()
        task = Task(
            title="t", description="d",
            task_type="artifact.binary_triage",
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "binary_files": ["stfu"],
            },
        )
        state = _state(category=category)
        report = WorkerReport(
            task_id=task.task_id,
            worker_name=agent.name,
            success=True,
            summary="triage",
            output_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "inspected_binaries": ["stfu"],
                "flag_candidates": flag_candidates,
            },
        )
        agent._maybe_queue_disassembly_followup(task, state, report)
        return report

    def test_queues_followup_when_no_flag_and_crypto(self):
        report = self._build_triage_report_via_post_process(
            category="crypto", flag_candidates=[],
        )
        followups = [t for t in report.new_tasks if t.task_type == "artifact.binary_disassembly"]
        self.assertEqual(len(followups), 1)
        self.assertEqual(followups[0].input_context["binary_files"], ["stfu"])

    def test_skips_followup_when_flag_found(self):
        report = self._build_triage_report_via_post_process(
            category="crypto", flag_candidates=["flag{found}"],
        )
        self.assertFalse(
            any(t.task_type == "artifact.binary_disassembly" for t in report.new_tasks)
        )

    def test_skips_followup_for_non_re_category(self):
        report = self._build_triage_report_via_post_process(
            category="web", flag_candidates=[],
        )
        self.assertFalse(
            any(t.task_type == "artifact.binary_disassembly" for t in report.new_tasks)
        )


class BinaryDisassemblyTaskFactoryTests(unittest.TestCase):
    def test_dedupe_key_stable(self):
        a = build_binary_disassembly_task(
            files_root="/x", binary_files=["a", "b"],
        )
        b = build_binary_disassembly_task(
            files_root="/x", binary_files=["a", "b"],
        )
        self.assertEqual(a.dedupe_key, b.dedupe_key)

    def test_priority_below_triage(self):
        # The deep pass is more expensive — triage should win the queue.
        triage = build_binary_triage_task(
            files_root="/x", binary_files=["a"],
        )
        deep = build_binary_disassembly_task(
            files_root="/x", binary_files=["a"],
        )
        self.assertLess(deep.priority, triage.priority)


class BinaryRunTaskFactoryTests(unittest.TestCase):
    """Sandbox-run task is the LAST resort — verify ordering."""

    def test_dedupe_key_stable(self):
        a = build_binary_run_task(files_root="/x", binary_files=["a"])
        b = build_binary_run_task(files_root="/x", binary_files=["a"])
        self.assertEqual(a.dedupe_key, b.dedupe_key)
        self.assertEqual(a.task_type, "artifact.binary_run")

    def test_priority_below_disassembly_and_triage(self):
        triage = build_binary_triage_task(files_root="/x", binary_files=["a"])
        disasm = build_binary_disassembly_task(files_root="/x", binary_files=["a"])
        runt = build_binary_run_task(files_root="/x", binary_files=["a"])
        # triage > disassembly > run — cheapest signal first.
        self.assertLess(runt.priority, disasm.priority)
        self.assertLess(disasm.priority, triage.priority)


class BinaryDisassemblyToRunFollowupTests(unittest.TestCase):
    """After a disassembly that yielded no flag in a rev/pwn/crypto challenge,
    the agent must auto-queue a sandboxed ``artifact.binary_run`` follow-up.
    """

    def _build_disasm_report(self, *, category: str, flag_candidates: list[str]):
        from killchain_docker.state import WorkerReport

        agent = BinaryTriageAgent()
        task = Task(
            title="d", description="d",
            task_type="artifact.binary_disassembly",
            input_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "binary_files": ["stfu"],
            },
        )
        state = _state(category=category)
        report = WorkerReport(
            task_id=task.task_id,
            worker_name=agent.name,
            success=True,
            summary="disasm",
            output_context={
                "files_root": "/home/ctfplayer/ctf_files",
                "inspected_binaries": ["stfu"],
                "flag_candidates": flag_candidates,
            },
        )
        agent._maybe_queue_binary_run_followup(task, state, report)
        return report

    def test_queues_run_followup_when_no_flag_and_crypto(self):
        report = self._build_disasm_report(category="crypto", flag_candidates=[])
        followups = [t for t in report.new_tasks if t.task_type == "artifact.binary_run"]
        self.assertEqual(len(followups), 1)
        self.assertEqual(followups[0].input_context["binary_files"], ["stfu"])

    def test_skips_run_followup_when_flag_found(self):
        report = self._build_disasm_report(
            category="crypto", flag_candidates=["flag{found}"],
        )
        self.assertFalse(
            any(t.task_type == "artifact.binary_run" for t in report.new_tasks)
        )

    def test_skips_run_followup_for_non_re_category(self):
        report = self._build_disasm_report(category="web", flag_candidates=[])
        self.assertFalse(
            any(t.task_type == "artifact.binary_run" for t in report.new_tasks)
        )


class SolverEvidenceBinaryRunsPickupTests(unittest.TestCase):
    """Solver evidence must merge binary_run tool output into snapshot."""

    def test_picks_up_single_binary_run_record(self):
        state = _state()
        ev = EvidenceRecord(
            task_id="task-bin-run",
            tool_name="binary_run",
            mode="cli",
            summary="run",
            request={},
            result={},
            extracted={
                "output_context": {
                    "binary_runs": {
                        "stfu": {
                            "binary": "stfu",
                            "invocations": [
                                {
                                    "label": "no-args",
                                    "argv": ["./stfu"],
                                    "returncode": 1,
                                    "stdout_preview": "",
                                    "stderr_preview": "Usage: stfu <FILE>",
                                    "new_files": [],
                                },
                            ],
                        },
                    },
                },
            },
        )
        state.upsert_evidence(ev)
        composer = SolverEvidenceComposer()
        task = Task(
            title="s", description="d",
            task_type="solve.generate_script",
            input_context={"files_root": "/home/ctfplayer/ctf_files"},
        )
        evidence = composer.compose(task, state)
        self.assertIn("stfu", evidence.binary_runs)
        snap = evidence.to_snapshot()
        self.assertIn("binary_runs", snap)
        self.assertEqual(
            snap["binary_runs"]["stfu"]["invocations"][0]["label"], "no-args",
        )


class SolverEvidenceDisassemblyPickupTests(unittest.TestCase):
    """The solver evidence composer must merge binary_disassembly tool output
    into ``evidence.binary_disassembly`` so the prompt can show concrete
    function bodies + .rodata to the LLM."""

    def test_picks_up_single_disassembly_record(self):
        state = _state()
        ev = _disassembly_evidence(task_id="task-fake01")
        state.upsert_evidence(ev)

        composer = SolverEvidenceComposer()
        task = Task(
            title="Solve", description="d",
            task_type="solve.generate_script",
            input_context={"files_root": "/home/ctfplayer/ctf_files"},
        )
        evidence = composer.compose(task, state)
        self.assertIn("stfu", evidence.binary_disassembly)
        snap = evidence.to_snapshot()
        self.assertIn("binary_disassembly", snap)
        self.assertEqual(
            snap["binary_disassembly"]["stfu"]["function_count_kept"], 3,
        )

    def test_ignores_unrelated_tools(self):
        state = _state()
        other = EvidenceRecord(
            task_id="task-other",
            tool_name="binary_triage",  # not the disassembly tool
            mode="cli",
            summary="strings only",
            request={},
            result={},
            extracted={
                "output_context": {
                    "disassembly": {
                        "stfu": {"functions": [{"name": "main"}]},
                    },
                },
            },
        )
        state.upsert_evidence(other)
        evidence = SolverEvidenceComposer().compose(
            Task(
                title="x", description="d",
                task_type="solve.generate_script",
                input_context={"files_root": "/home/ctfplayer/ctf_files"},
            ),
            state,
        )
        # Wrong tool_name -> must not be merged.
        self.assertEqual(evidence.binary_disassembly, {})


if __name__ == "__main__":
    unittest.main()
