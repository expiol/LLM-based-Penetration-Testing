"""Tests for the binary disassembly agent path and planner signals."""

from __future__ import annotations

import unittest

from killchain_docker.workers.artifact import BinaryTriageAgent
from killchain_docker.state import GlobalState, Task
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


class BinaryTriageFollowupSignalTests(unittest.TestCase):
    """After a triage with no flag in a rev/pwn/crypto challenge, the agent
    should emit a planner signal for a disassembly follow-up."""

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
        signals = [
            signal for signal in report.planner_signals
            if signal.suggested_task_type == "artifact.binary_disassembly"
        ]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].suggested_input_context["binary_files"], ["stfu"])

    def test_skips_followup_when_flag_found(self):
        report = self._build_triage_report_via_post_process(
            category="crypto", flag_candidates=["flag{found}"],
        )
        self.assertFalse(
            any(
                signal.suggested_task_type == "artifact.binary_disassembly"
                for signal in report.planner_signals
            )
        )

    def test_skips_followup_for_non_re_category(self):
        report = self._build_triage_report_via_post_process(
            category="web", flag_candidates=[],
        )
        self.assertFalse(
            any(
                signal.suggested_task_type == "artifact.binary_disassembly"
                for signal in report.planner_signals
            )
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


class BinaryDisassemblyToRunSignalTests(unittest.TestCase):
    """After a disassembly that yielded no flag in a rev/pwn/crypto challenge,
    the agent should emit a sandboxed ``artifact.binary_run`` planner signal.
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
        signals = [
            signal for signal in report.planner_signals
            if signal.suggested_task_type == "artifact.binary_run"
        ]
        self.assertEqual(len(signals), 1)
        self.assertEqual(signals[0].suggested_input_context["binary_files"], ["stfu"])

    def test_skips_run_followup_when_flag_found(self):
        report = self._build_disasm_report(
            category="crypto", flag_candidates=["flag{found}"],
        )
        self.assertFalse(
            any(
                signal.suggested_task_type == "artifact.binary_run"
                for signal in report.planner_signals
            )
        )

    def test_skips_run_followup_for_non_re_category(self):
        report = self._build_disasm_report(category="web", flag_candidates=[])
        self.assertFalse(
            any(
                signal.suggested_task_type == "artifact.binary_run"
                for signal in report.planner_signals
            )
        )


if __name__ == "__main__":
    unittest.main()
