"""Tests for the split SolverAgent pipeline."""

from __future__ import annotations

import unittest

from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver import (
    SolverAgent,
    SolverEvidence,
    SolverEvidenceComposer,
    SolverExecutionOutcome,
    SolverFlagSet,
    SolverPromptBuilder,
    SolverResultParser,
    SolverRetryPolicy,
)
from nyuctf_mutil_killchain.agents.solver.parser import (
    clean_near_miss_candidates,
    is_placeholder_flag,
)
from nyuctf_mutil_killchain.llm import StaticLLMClient
from nyuctf_mutil_killchain.state import GlobalState, Task


def _state_with_files(files: list[str], category: str = "crypto") -> GlobalState:
    return GlobalState(
        objective="Solve test challenge.",
        authorized_scope=[],
        metadata={
            "challenge": {
                "name": "test",
                "category": category,
                "flag_format": "flag{...}",
                "files": files,
                "server_name": "",
                "port": None,
            }
        },
    )


def _solve_task(extra_ctx: dict | None = None) -> Task:
    ctx = {"files_root": "/home/ctfplayer/ctf_files"}
    if extra_ctx:
        ctx.update(extra_ctx)
    return Task(
        title="Solve",
        description="Generate and execute a solver.",
        task_type="solve.generate_script",
        priority=95,
        input_context=ctx,
        dedupe_key="solver-1",
    )


class SolverEvidenceTests(unittest.TestCase):
    def test_composer_collects_basic_challenge_metadata(self):
        state = _state_with_files(["stfu", "flag.stfu"])
        task = _solve_task()
        composer = SolverEvidenceComposer()
        evidence = composer.compose(task, state)

        self.assertEqual(evidence.category, "crypto")
        self.assertEqual(evidence.files_root, "/home/ctfplayer/ctf_files")
        # Both files are classified as binary -> notes only, no content
        self.assertEqual(len(evidence.challenge_source_files), 2)
        for entry in evidence.challenge_source_files:
            self.assertIn("note", entry)

    def test_composer_picks_up_attempt_number(self):
        state = _state_with_files(["solve.py"])
        task = _solve_task({"attempt_number": 3, "previous_attempts": [{"attempt": 2}]})
        evidence = SolverEvidenceComposer().compose(task, state)
        self.assertEqual(evidence.attempt_number, 3)
        self.assertEqual(len(evidence.previous_attempts), 1)


class SolverParserTests(unittest.TestCase):
    def test_placeholder_flag_detection(self):
        self.assertTrue(is_placeholder_flag("flag{not_found}"))
        self.assertTrue(is_placeholder_flag("flag{placeholder}"))
        self.assertTrue(is_placeholder_flag("key{TODO}"))
        self.assertFalse(is_placeholder_flag("flag{real_secret_value}"))

    def test_clean_near_miss_strips_nonprintable(self):
        candidates = ["flag{abc\x01\x02def}", "flag{nope}"]
        cleaned = clean_near_miss_candidates(candidates)
        self.assertIn("flag{abcdef}", cleaned)

    def test_extract_filters_placeholders(self):
        guidance = SolverCodeGuidance(
            summary="ok",
            solver_code="print('flag{x}')",
            grounded_flag_candidates=["flag{not_found}", "flag{real_value}"],
        )
        outcome = SolverExecutionOutcome(
            success=True,
            bundle=None,
            error=None,
            output_context={"flag_candidates": ["flag{real_value}"]},
            summary="ok",
        )
        flag_set = SolverResultParser().extract(outcome, guidance)
        self.assertEqual(flag_set.flag_candidates, ["flag{real_value}"])


class SolverRetryTests(unittest.TestCase):
    def test_retry_skipped_when_flag_found(self):
        state = _state_with_files(["solve.py"])
        task = _solve_task()
        evidence = SolverEvidenceComposer().compose(task, state)
        outcome = SolverExecutionOutcome(
            success=True, bundle=None, error=None,
            output_context={"returncode": 0, "stdout": "flag{x}", "stderr": ""},
            summary="ok",
        )
        flags = SolverFlagSet(flag_candidates=["flag{x}"])
        guidance = SolverCodeGuidance(summary="ok", solver_code="print('x')")
        plan = SolverRetryPolicy().decide(
            task=task, evidence=evidence, outcome=outcome, flags=flags, guidance=guidance,
        )
        self.assertFalse(plan.should_retry)

    def test_retry_scheduled_on_no_flag(self):
        state = _state_with_files(["solve.py"])
        task = _solve_task()
        evidence = SolverEvidenceComposer().compose(task, state)
        outcome = SolverExecutionOutcome(
            success=True, bundle=None, error=None,
            output_context={"returncode": 1, "stdout": "", "stderr": "boom"},
            summary="fail",
        )
        flags = SolverFlagSet(flag_candidates=[])
        guidance = SolverCodeGuidance(
            summary="ok",
            solver_code="print('x')",
            should_retry_on_failure=True,
        )
        plan = SolverRetryPolicy().decide(
            task=task, evidence=evidence, outcome=outcome, flags=flags, guidance=guidance,
        )
        self.assertTrue(plan.should_retry)
        self.assertEqual(plan.retry_task.task_type, "solve.generate_script")
        self.assertEqual(plan.retry_task.input_context["attempt_number"], 2)

    def test_retry_caps_at_max(self):
        state = _state_with_files(["solve.py"])
        task = _solve_task({"attempt_number": 4})
        evidence = SolverEvidenceComposer().compose(task, state)
        evidence.attempt_number = 4
        outcome = SolverExecutionOutcome(
            success=True, bundle=None, error=None,
            output_context={"returncode": 1},
            summary="fail",
        )
        flags = SolverFlagSet(flag_candidates=[])
        guidance = SolverCodeGuidance(
            summary="ok", solver_code="x", should_retry_on_failure=True,
        )
        plan = SolverRetryPolicy(max_retries=4).decide(
            task=task, evidence=evidence, outcome=outcome, flags=flags, guidance=guidance,
        )
        self.assertFalse(plan.should_retry)


class SolverPromptTests(unittest.TestCase):
    def test_prompt_builder_returns_two_strings(self):
        state = _state_with_files(["solve.py"])
        evidence = SolverEvidenceComposer().compose(_solve_task(), state)
        sys_p, usr_p = SolverPromptBuilder().build(evidence)
        self.assertIn("CTF solver", sys_p)
        self.assertIn("solve.py", usr_p)


class SolverAgentIntegrationTests(unittest.TestCase):
    def test_agent_fails_without_llm(self):
        agent = SolverAgent()
        state = _state_with_files(["solve.py"])
        report = agent.run(_solve_task(), state)
        self.assertFalse(report.success)
        self.assertIn("LLM client", report.summary)

    def test_agent_fails_without_execution_plane(self):
        agent = SolverAgent(llm_client=StaticLLMClient([]))
        state = _state_with_files(["solve.py"])
        report = agent.run(_solve_task(), state)
        self.assertFalse(report.success)
        self.assertIn("execution plane", report.summary)


if __name__ == "__main__":
    unittest.main()
