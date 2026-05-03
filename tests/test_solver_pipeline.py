"""Tests for the split SolverAgent pipeline."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

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
from nyuctf_mutil_killchain.knowledge import KnowledgeAugmenter, KnowledgeRetriever
from nyuctf_mutil_killchain.knowledge.corpus import KnowledgeEntry
from nyuctf_mutil_killchain.knowledge.embedder import StubEmbedder
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

    def test_composer_without_augmenter_emits_empty_writeups(self):
        state = _state_with_files(["solve.py"])
        evidence = SolverEvidenceComposer().compose(_solve_task(), state)
        self.assertEqual(evidence.related_writeups, [])
        # ``to_snapshot`` should also drop the empty key entirely.
        self.assertNotIn("related_writeups", evidence.to_snapshot())


class SolverEvidenceRagTests(unittest.TestCase):
    """Verify the augmenter feeds writeup hits into solver evidence + prompt."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        entries = [
            KnowledgeEntry(
                challenge_id="2013f-cry-stfu",
                year="2013",
                event="CSAW-Finals",
                category="crypto",
                name="stfu",
                description="LFSR-based file encryption with 16-byte header.",
                files=["stfu", "flag.stfu"],
                writeup="",
                solution_sketch=(
                    "Read seed/tap/skip from header bytes 4-16, run LFSR, "
                    "XOR the keystream against the body to recover the flag."
                ),
            ),
        ]
        self.retriever = KnowledgeRetriever(
            entries, embedder=StubEmbedder(), cache_dir=self.tmp
        )
        self.augmenter = KnowledgeAugmenter(self.retriever)

    def _stfu_state(self) -> GlobalState:
        return GlobalState(
            objective="LFSR-based file encryption stored in a Secure Test File Unit.",
            authorized_scope=[],
            metadata={
                "challenge": {
                    "name": "stfu",
                    "category": "crypto",
                    "flag_format": "",
                    "files": ["stfu", "flag.stfu"],
                    "year": "2013",
                    "event": "CSAW-Finals",
                    "canonical_name": "2013f-cry-stfu",
                }
            },
        )

    def test_evidence_carries_writeups_when_augmenter_present(self):
        composer = SolverEvidenceComposer(augmenter=self.augmenter)
        evidence = composer.compose(_solve_task(), self._stfu_state())
        self.assertGreaterEqual(len(evidence.related_writeups), 1)
        first = evidence.related_writeups[0]
        for required in ("challenge_id", "solution_sketch", "score"):
            self.assertIn(required, first)
        self.assertIn("LFSR", first["solution_sketch"])

    def test_user_prompt_serializes_writeups(self):
        composer = SolverEvidenceComposer(augmenter=self.augmenter)
        evidence = composer.compose(_solve_task(), self._stfu_state())
        _sys, user = SolverPromptBuilder().build(evidence)
        payload = json.loads(user)
        self.assertIn("related_writeups", payload)
        self.assertIn("LFSR", payload["related_writeups"][0]["solution_sketch"])

    def test_solver_agent_propagates_augmenter_to_default_composer(self):
        agent = SolverAgent(
            llm_client=StaticLLMClient([]),
            augmenter=self.augmenter,
        )
        evidence = agent.composer.compose(_solve_task(), self._stfu_state())
        self.assertGreaterEqual(len(evidence.related_writeups), 1)


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


class SolverLintExhaustionSoftFailTests(unittest.TestCase):
    """Lint exhaustion must produce WorkerReport(success=False), NOT LLMClientError.

    The orchestrator can then count the failed run toward the streak detector
    and route the next cycle to a different worker, instead of tearing the
    whole task down.
    """

    def test_all_empty_solver_code_yields_soft_failure(self):
        from nyuctf_mutil_killchain.agents.solver.agent import (
            SolverAgent,
            _LINT_RETRY_BUDGET,
        )

        empty_payload = {
            "summary": "always empty",
            "solver_code": "",
            "solver_language": "python",
        }
        # Provide one response per attempt the lint loop will make.
        responses = [empty_payload] * (_LINT_RETRY_BUDGET + 1)

        class _NoopExecutor:
            def run(self, **kwargs):  # pragma: no cover - shouldn't be reached
                raise AssertionError("Executor must not run when lint exhausts.")

        agent = SolverAgent(
            llm_client=StaticLLMClient(responses),
            executor=_NoopExecutor(),
        )
        state = _state_with_files(["solve.py"])
        report = agent.run(_solve_task(), state)
        self.assertFalse(report.success)
        self.assertIn("Solver execution failed", report.summary)
        self.assertIn("lint", report.summary)
        # Soft fail must not be retryable; planner should diversify.
        self.assertFalse(report.retryable)


class LLMClientSolverFallbackTests(unittest.TestCase):
    """LLM transport / parse failures collapse to empty SolverCodeGuidance."""

    def test_validation_failure_falls_back_to_empty_solver_code(self):
        # Payload missing solver_code entirely — would previously raise
        # LLMClientError("LLM response failed SolverCodeGuidance validation").
        # Should now return an empty SolverCodeGuidance so the lint loop
        # surfaces it as error_kind="empty" and re-prompts.
        client = StaticLLMClient([{"summary": "no code field at all"}])
        guidance = client.generate_json(
            system_prompt="x",
            user_prompt="y",
            schema=SolverCodeGuidance,
        )
        self.assertEqual(guidance.solver_code, "")
        self.assertIn("validation", guidance.summary.lower())

    def test_solver_validation_fallback_is_not_an_exception(self):
        # The solver-side fallback returns an empty SolverCodeGuidance rather
        # than letting Pydantic ValidationError out — so the lint loop sees
        # the failure as ``error_kind="empty"`` and re-prompts.  Verifies
        # the fallback path is actually exercised (no exception leaks).
        client = StaticLLMClient(
            [
                {
                    "summary": "x",
                    "solver_code": "import sys\nprint('a')\n",
                    "confidence": "not-a-number-or-label",
                }
            ]
        )
        guidance = client.generate_json(
            system_prompt="x",
            user_prompt="y",
            schema=SolverCodeGuidance,
        )
        # Either the bad confidence got swallowed by fallback (empty
        # solver_code with diagnostic summary) or the schema's existing
        # ``coerce_confidence`` validator absorbed it.  Both are acceptable;
        # the contract is "no exception escapes for SolverCodeGuidance".
        self.assertIsNotNone(guidance)


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
