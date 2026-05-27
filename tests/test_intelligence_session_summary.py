"""Tests for ``maybe_refresh_session_summary``.

Covers the cycle-based gating thresholds (initial floor + minimum gap between
updates) and the projection of run state into the in-run summary entry.
"""

from __future__ import annotations

import unittest

from killchain_docker.intelligence.session import (
    DEFAULT_THRESHOLDS,
    SESSION_SUMMARY_KEY,
    SessionSummaryThresholds,
    maybe_refresh_session_summary,
)
from killchain_docker.state.domain import ExecutionRecord
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import RouterRound, RouterRoundSummary


def _make_state(**overrides: object) -> RunState:
    base: dict[str, object] = {
        "objective": "Recover the LFSR cipher and submit the flag.",
        "scope": [],
    }
    base.update(overrides)
    return RunState(**base)


class GatingTests(unittest.TestCase):
    def test_below_minimum_cycles_to_init_returns_false(self) -> None:
        state = _make_state()
        self.assertFalse(maybe_refresh_session_summary(state, cycle=2))
        self.assertNotIn(SESSION_SUMMARY_KEY, state.run_memory)
        self.assertNotIn("session_summary_cycle", state.metadata)

    def test_initial_refresh_at_minimum_cycles(self) -> None:
        state = _make_state()
        self.assertTrue(maybe_refresh_session_summary(state, cycle=3))
        self.assertIn(SESSION_SUMMARY_KEY, state.run_memory)
        self.assertEqual(state.metadata.get("session_summary_cycle"), 3)

    def test_blocks_refresh_within_minimum_gap(self) -> None:
        state = _make_state()
        self.assertTrue(maybe_refresh_session_summary(state, cycle=3))
        first_summary = state.run_memory[SESSION_SUMMARY_KEY]
        # Default gap is 2 cycles; cycle=4 is only 1 cycle later, so the
        # gate should still be closed and the stored summary untouched.
        self.assertFalse(maybe_refresh_session_summary(state, cycle=4))
        self.assertEqual(state.run_memory[SESSION_SUMMARY_KEY], first_summary)
        self.assertEqual(state.metadata.get("session_summary_cycle"), 3)

    def test_allows_refresh_after_minimum_gap(self) -> None:
        state = _make_state()
        self.assertTrue(maybe_refresh_session_summary(state, cycle=3))
        # Add a round so the second projection differs from the first; this
        # also documents that the summary keeps up with new evidence.
        state.rounds.append(
            RouterRound(
                cycle=4,
                planner_summary="explored encoding",
                summary=RouterRoundSummary(summary="found AES-CBC oracle pattern"),
            )
        )
        self.assertTrue(maybe_refresh_session_summary(state, cycle=5))
        self.assertEqual(state.metadata.get("session_summary_cycle"), 5)
        self.assertIn("AES-CBC oracle pattern", state.run_memory[SESSION_SUMMARY_KEY])

    def test_custom_thresholds_override_defaults(self) -> None:
        state = _make_state()
        thresholds = SessionSummaryThresholds(
            minimum_cycles_to_init=5,
            minimum_cycles_between_updates=4,
        )
        self.assertFalse(
            maybe_refresh_session_summary(state, cycle=4, thresholds=thresholds)
        )
        self.assertTrue(
            maybe_refresh_session_summary(state, cycle=5, thresholds=thresholds)
        )

    def test_default_thresholds_match_documented_floors(self) -> None:
        # Other modules read these as project-wide invariants, so guard them.
        self.assertEqual(DEFAULT_THRESHOLDS.minimum_cycles_to_init, 3)
        self.assertEqual(DEFAULT_THRESHOLDS.minimum_cycles_between_updates, 2)


class RenderSummaryTests(unittest.TestCase):
    def test_summary_includes_objective_and_counters(self) -> None:
        state = _make_state(objective="Find a way past the login form.")
        maybe_refresh_session_summary(state, cycle=3)
        text = state.run_memory[SESSION_SUMMARY_KEY]
        self.assertIn("objective: Find a way past the login form.", text)
        self.assertIn("rounds=0", text)
        self.assertIn("todos=0", text)
        self.assertIn("findings=0", text)

    def test_summary_includes_last_round_summary_when_present(self) -> None:
        state = _make_state()
        state.rounds.append(
            RouterRound(
                cycle=1,
                summary=RouterRoundSummary(summary="enumerated /admin endpoints"),
            )
        )
        maybe_refresh_session_summary(state, cycle=3)
        self.assertIn(
            "last_round_summary: enumerated /admin endpoints",
            state.run_memory[SESSION_SUMMARY_KEY],
        )

    def test_summary_includes_last_execution_summary_when_present(self) -> None:
        state = _make_state()
        state.execution_log.append(
            ExecutionRecord(
                task_id="task-1",
                worker_name="recon-worker",
                success=True,
                summary="nmap top-1000 scan finished",
            )
        )
        maybe_refresh_session_summary(state, cycle=3)
        self.assertIn(
            "last_step: nmap top-1000 scan finished",
            state.run_memory[SESSION_SUMMARY_KEY],
        )

    def test_summary_truncates_long_objective(self) -> None:
        long_objective = "A" * 600
        state = _make_state(objective=long_objective)
        maybe_refresh_session_summary(state, cycle=3)
        text = state.run_memory[SESSION_SUMMARY_KEY]
        # Objective is truncated to 240 chars in the projection.
        self.assertIn("A" * 240, text)
        self.assertNotIn("A" * 241, text)


if __name__ == "__main__":
    unittest.main()
