"""Core orchestration policy tests."""

from __future__ import annotations

import unittest

from killchain_docker.orchestrator.planning import PlanningPipeline
from killchain_docker.orchestrator.policy import CandidatePolicy, ProgressPolicy, TodoPolicy
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.state import FlagCandidate, RunState, StateDelta, TodoItem, TodoPhase


def _state(flag_format: str = "flag{...}") -> RunState:
    return RunState(
        objective="solve",
        metadata={"challenge": {"flag_format": flag_format, "files": ["stfu", "flag.stfu"]}},
    )


class CandidatePolicyTests(unittest.TestCase):
    def test_rejects_escaped_byte_prefix_candidate_at_state_boundary(self) -> None:
        state = _state("flag{...}")
        state.apply_state_delta(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(value=r"flag{\x96\xff\xa0\rabcd}", source="script.exec")
                ]
            )
        )

        self.assertEqual(state.flag_candidates, {})
        self.assertTrue(any("escaped_byte_candidate" in note for note in state.orchestration_notes))

    def test_unknown_format_accepts_both_bare_and_prefix_candidates(self) -> None:
        state = _state("")
        state.apply_state_delta(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(value="flag{wrong_for_this_challenge}", source="script.exec"),
                    FlagCandidate(value="STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME", source="script.exec"),
                ]
            )
        )

        # Empty flag_format means "unknown" — accepts both bare tokens and prefix candidates
        self.assertEqual(
            [candidate.value for candidate in state.flag_candidates.values()],
            ["flag{wrong_for_this_challenge}", "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"],
        )

    def test_prefix_challenge_rejects_wrong_prefix(self) -> None:
        state = _state("key{...}")
        self.assertFalse(CandidatePolicy.accepts_for_state(state, "flag{correct_length_body}"))
        self.assertTrue(CandidatePolicy.accepts_for_state(state, "key{correct_length_body}"))

    def test_rejected_candidate_does_not_trigger_validation_seed(self) -> None:
        state = _state("")
        state.apply_state_delta(
            StateDelta(flag_candidates=[FlagCandidate(value=r"flag{\x96\xffabcd}", source="script")])
        )

        decision = PlanningPipeline().plan(state)

        self.assertFalse(any(todo.phase == TodoPhase.FLAG_VALIDATION for todo in decision.todos))


class TodoProgressPolicyTests(unittest.TestCase):
    def test_compound_binary_then_script_todo_becomes_analysis_only(self) -> None:
        state = _state()
        todo = PlannedTodo(
            goal="Extract objdump disassembly and then write a Python script to decrypt flag.stfu.",
            phase=TodoPhase.EXPLOIT,
        )

        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertEqual(todo.context["family"], "binary-analysis")
        self.assertEqual(todo.context["capability_hint"], "shell.exec")

    def test_failed_family_enters_cooldown_without_novelty(self) -> None:
        state = _state()
        for idx in range(ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD):
            item = state.queue_todo(
                TodoItem(
                    goal=f"Try LFSR decrypt variant {idx}",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "lfsr-decrypt"},
                    dedupe_key=f"lfsr-{idx}",
                )
            )
            item.mark_running("exploit-worker")
            item.mark_partial("Script execution ran without recovering a flag.", "no candidate")

        todo = PlannedTodo(
            goal="Try LFSR decrypt variant N+1",
            phase=TodoPhase.ANALYSIS,
            context={"family": "lfsr-decrypt"},
        )

        allowed, reason = ProgressPolicy.allows(todo, state)

        self.assertFalse(allowed)
        self.assertIn("cooldown", reason)

    def test_failed_family_allows_new_novelty_key(self) -> None:
        state = _state()
        for idx in range(ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD):
            item = state.queue_todo(
                TodoItem(
                    goal=f"Try LFSR decrypt variant {idx}",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "lfsr-decrypt"},
                    dedupe_key=f"lfsr-{idx}",
                )
            )
            item.mark_running("exploit-worker")
            item.mark_failed("candidate mismatch", retryable=False)

        todo = PlannedTodo(
            goal="Retry LFSR decrypt using newly extracted loop evidence.",
            phase=TodoPhase.ANALYSIS,
            context={"family": "lfsr-decrypt", "novelty_key": "main-loop-offset"},
        )

        allowed, _reason = ProgressPolicy.allows(todo, state)

        self.assertTrue(allowed)

    def test_failed_family_allows_materially_different_goal(self) -> None:
        state = _state()
        for idx in range(ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD):
            item = state.queue_todo(
                TodoItem(
                    goal=f"Try LFSR decrypt variant {idx} with skip cap",
                    phase=TodoPhase.ANALYSIS,
                    context={"family": "lfsr-decrypt"},
                    dedupe_key=f"lfsr-{idx}",
                )
            )
            item.mark_running("exploit-worker")
            item.mark_partial("Script execution ran without recovering a flag.", "no candidate")

        todo = PlannedTodo(
            goal="Pivot away from LFSR: try AES counter-mode keystream from header bytes.",
            phase=TodoPhase.ANALYSIS,
            context={"family": "lfsr-decrypt"},
        )

        allowed, _reason = ProgressPolicy.allows(todo, state)

        self.assertTrue(allowed)


class FlagValidationCapTests(unittest.TestCase):
    def test_same_candidate_blocked_after_cap(self) -> None:
        """Repeated validation of the same candidate value is capped."""
        state = _state()
        for idx in range(ProgressPolicy.MAX_FLAG_VALIDATION_ATTEMPTS):
            item = state.queue_todo(
                TodoItem(
                    goal=f"Validate flag candidate attempt {idx}",
                    phase=TodoPhase.FLAG_VALIDATION,
                    context={"family": "flag-validation", "candidate_flag": "flag{test}"},
                    dedupe_key=f"flag-val-{idx}",
                )
            )
            item.mark_running("flag-worker")
            item.mark_failed("candidate mismatch", retryable=False)

        todo = PlannedTodo(
            goal="Validate flag candidate again",
            phase=TodoPhase.FLAG_VALIDATION,
            context={"family": "flag-validation", "candidate_flag": "flag{test}"},
        )

        allowed, reason = ProgressPolicy.allows(todo, state)

        self.assertFalse(allowed)
        self.assertIn("already validated", reason)

    def test_same_candidate_allows_under_cap(self) -> None:
        """Under the cap, repeated validation of the same candidate is allowed."""
        state = _state()
        item = state.queue_todo(
            TodoItem(
                goal="Validate flag candidate attempt 0",
                phase=TodoPhase.FLAG_VALIDATION,
                context={"family": "flag-validation", "candidate_flag": "flag{test}"},
                dedupe_key="flag-val-0",
            )
        )
        item.mark_running("flag-worker")
        item.mark_failed("candidate mismatch", retryable=False)

        todo = PlannedTodo(
            goal="Validate flag candidate attempt 1",
            phase=TodoPhase.FLAG_VALIDATION,
            context={"family": "flag-validation", "candidate_flag": "flag{test}"},
        )

        allowed, _reason = ProgressPolicy.allows(todo, state)

        self.assertTrue(allowed)

    def test_different_candidate_always_allowed(self) -> None:
        """A new candidate value is never blocked by prior validation attempts."""
        state = _state()
        # Exhaust cap for one candidate
        for idx in range(ProgressPolicy.MAX_FLAG_VALIDATION_ATTEMPTS + 2):
            item = state.queue_todo(
                TodoItem(
                    goal=f"Validate flag{{old}} attempt {idx}",
                    phase=TodoPhase.FLAG_VALIDATION,
                    context={"family": "flag-validation", "candidate_flag": "flag{old}"},
                    dedupe_key=f"flag-val-old-{idx}",
                )
            )
            item.mark_running("flag-worker")
            item.mark_failed("candidate mismatch", retryable=False)

        # A different candidate must still be allowed
        todo = PlannedTodo(
            goal="Validate new candidate",
            phase=TodoPhase.FLAG_VALIDATION,
            context={"family": "flag-validation", "candidate_flag": "flag{new_value}"},
        )

        allowed, _reason = ProgressPolicy.allows(todo, state)

        self.assertTrue(allowed)


if __name__ == "__main__":
    unittest.main()
