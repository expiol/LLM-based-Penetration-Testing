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

    def test_has_real_flag_ignores_plaintext_status_lines(self):
        # Plaintext candidates can still be scheduled for validation, but should
        # not suppress solver retry decisions as if we had a real prefix{...} flag.
        flags = SolverFlagSet(
            flag_candidates=[
                "Encrypted test length: 44",
                "Trying cmd: ['/home/ctfplayer/ctf_files/stfu', 'x', 'y']",
                "no args: Usage: /home/ctfplayer/ctf_files/stfu <FILE>",
            ]
        )
        self.assertFalse(flags.has_real_flag)

    def test_has_real_flag_true_for_structured_token(self):
        flags = SolverFlagSet(flag_candidates=["flag{test123}"])
        self.assertTrue(flags.has_real_flag)


class SolverRetryTests(unittest.TestCase):
    def test_retry_skipped_when_flag_found(self):
        state = _state_with_files(["solve.py"])
        task = _solve_task()
        evidence = SolverEvidenceComposer().compose(task, state)
        outcome = SolverExecutionOutcome(
            success=True, bundle=None, error=None,
            output_context={"returncode": 0, "stdout": "flag{real_value}", "stderr": ""},
            summary="ok",
        )
        flags = SolverFlagSet(flag_candidates=["flag{real_value}"])
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


class SolverEmptyCodeRecoveryTests(unittest.TestCase):
    """Empty ``solver_code`` from the LLM must be recovered by the lint loop,
    not raised at the LLM-client level (which would kill the cycle)."""

    def test_empty_then_valid_recovers(self):
        from nyuctf_mutil_killchain.agents.solver.agent import SolverAgent

        # First response is empty; second response is a valid script.  The
        # lint loop should re-prompt and accept the second.
        responses = [
            {
                "summary": "first attempt",
                "solver_code": "",
                "solver_language": "python",
                "should_retry_on_failure": True,
            },
            {
                "summary": "second attempt",
                "solver_code": "import sys\nprint('flag{ok}')\n",
                "solver_language": "python",
                "should_retry_on_failure": True,
            },
        ]
        client = StaticLLMClient(responses)
        agent = SolverAgent(llm_client=client)
        state = _state_with_files(["solve.py"])
        evidence = SolverEvidenceComposer().compose(_solve_task(), state)
        guidance, lint_attempts = agent._generate_lint_clean_solver_code(evidence)
        self.assertEqual(lint_attempts, 1)
        self.assertIn("flag{ok}", guidance.solver_code)


class SolverCodeRecoveryTests(unittest.TestCase):
    """Recovering ``SolverCodeGuidance`` from a non-JSON LLM response."""

    def test_recovery_wraps_raw_python_as_solver_code(self):
        from nyuctf_mutil_killchain.agents.reasoning.schemas import SolverCodeGuidance
        from nyuctf_mutil_killchain.llm.client import (
            _looks_like_solver_code,
            _recover_solver_code_payload,
        )

        raw_text = (
            "import sys\n"
            "from pathlib import Path\n"
            "def solve():\n"
            "    print('hi')\n"
            "if __name__ == '__main__':\n"
            "    solve()\n"
        )
        self.assertTrue(_looks_like_solver_code(raw_text))
        payload = _recover_solver_code_payload(raw_text, SolverCodeGuidance)
        self.assertIsNotNone(payload)
        self.assertIn("solver_code", payload)  # type: ignore[arg-type]
        self.assertIn("import sys", payload["solver_code"])  # type: ignore[index]

    def test_recovery_skips_non_solver_schemas(self):
        from nyuctf_mutil_killchain.llm.client import _recover_solver_code_payload
        from nyuctf_mutil_killchain.orchestrator.router import WorkerRouteDecision

        payload = _recover_solver_code_payload(
            "import sys\ndef foo(): pass\n",
            WorkerRouteDecision,
        )
        self.assertIsNone(payload)

    def test_recovery_rejects_short_or_jsonish_text(self):
        from nyuctf_mutil_killchain.agents.reasoning.schemas import SolverCodeGuidance
        from nyuctf_mutil_killchain.llm.client import _recover_solver_code_payload

        self.assertIsNone(_recover_solver_code_payload("x", SolverCodeGuidance))
        # Only one marker hit — too weak to be considered a script.
        self.assertIsNone(
            _recover_solver_code_payload(
                '{"summary": "import was here in the prose"}',
                SolverCodeGuidance,
            )
        )


if __name__ == "__main__":
    unittest.main()
