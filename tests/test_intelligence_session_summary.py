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
from killchain_docker.intelligence.session.summary import MAX_SUMMARY_CHARS
from killchain_docker.memory.projection import RunMemoryProjection
from killchain_docker.state.domain import EvidenceRecord, ExecutionRecord, Finding
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import RouterRound, RouterRoundSummary, TodoItem


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

    def test_summary_rolls_up_old_rounds_and_evidence_refs(self) -> None:
        state = _make_state()
        for cycle in range(1, 5):
            state.rounds.append(
                RouterRound(
                    cycle=cycle,
                    planner_summary=f"planner chose phase {cycle}",
                    summary=RouterRoundSummary(
                        summary=f"cycle {cycle} recovered useful clue",
                        key_findings=[f"finding from cycle {cycle}"],
                        next_focus=f"continue from clue {cycle}",
                    ),
                )
            )
            state.evidence[f"evidence-{cycle}"] = EvidenceRecord(
                evidence_id=f"evidence-{cycle}",
                task_id=f"todo-{cycle}",
                capability="script.exec",
                tool_name="script_exec",
                mode="tool",
                summary=f"evidence summary {cycle}",
                extracted={
                    "output_context": {
                        "flag_candidates": [f"FLAG{{candidate-{cycle}}}"]
                    }
                },
            )
        state.findings["finding-1"] = Finding(
            finding_id="finding-1",
            title="Recovered XOR key",
            evidence_refs=["evidence-3"],
        )
        state.todos.append(TodoItem(goal="Validate recovered candidate."))
        maybe_refresh_session_summary(state, cycle=5)

        text = state.run_memory[SESSION_SUMMARY_KEY]
        self.assertIn("coverage: cycles=1-4", text)
        self.assertIn("round_rollup:", text)
        self.assertIn("cycle 4 recovered useful clue", text)
        self.assertIn("evidence_anchors:", text)
        self.assertIn("evidence-3", text)
        self.assertIn("FLAG{candidate-4}", text)
        self.assertIn("findings:", text)
        self.assertIn("Recovered XOR key", text)
        self.assertIn("open_focus:", text)
        self.assertEqual(
            state.metadata["session_summary"],
            {
                "key": SESSION_SUMMARY_KEY,
                "cycle": 5,
                "rounds": 4,
                "evidence": 4,
                "executions": 0,
            },
        )

    def test_summary_is_bounded(self) -> None:
        state = _make_state(objective="Summarize a noisy run.")
        for cycle in range(30):
            huge = f"cycle {cycle} " + ("X" * 1000)
            state.rounds.append(
                RouterRound(
                    cycle=cycle,
                    planner_summary=huge,
                    summary=RouterRoundSummary(summary=huge, key_findings=[huge]),
                )
            )
            state.evidence[f"evidence-{cycle}"] = EvidenceRecord(
                evidence_id=f"evidence-{cycle}",
                task_id=f"todo-{cycle}",
                tool_name="shell_exec",
                mode="tool",
                summary=huge,
            )

        maybe_refresh_session_summary(state, cycle=30)

        text = state.run_memory[SESSION_SUMMARY_KEY]
        self.assertLessEqual(len(text), MAX_SUMMARY_CHARS)
        self.assertIn("...[session summary truncated]", text)

    def test_summary_keeps_early_high_value_evidence_as_milestone(self) -> None:
        state = _make_state()
        state.evidence["evidence-early"] = EvidenceRecord(
            evidence_id="evidence-early",
            task_id="todo-early",
            tool_name="strings_cmd",
            mode="tool",
            summary="Recovered secret key material from the first artifact.",
            extracted={"output_context": {"flag_candidates": ["FLAG{early-secret}"]}},
        )
        for index in range(25):
            state.evidence[f"evidence-noise-{index}"] = EvidenceRecord(
                evidence_id=f"evidence-noise-{index}",
                task_id=f"todo-noise-{index}",
                tool_name="shell_exec",
                mode="tool",
                summary=f"routine diagnostic output {index}",
            )

        maybe_refresh_session_summary(state, cycle=5)

        text = state.run_memory[SESSION_SUMMARY_KEY]
        self.assertIn("historical_milestones:", text)
        self.assertIn("evidence-early", text)
        self.assertIn("FLAG{early-secret}", text)

    def test_projection_always_includes_session_summary_with_wider_budget(self) -> None:
        state = _make_state()
        state.run_memory.update({f"memory-{index}": "value" for index in range(25)})
        state.run_memory[SESSION_SUMMARY_KEY] = "S" * 1200

        projected = RunMemoryProjection(state).prompt_entries(limit=3, width=100)

        self.assertIn(SESSION_SUMMARY_KEY, projected)
        self.assertGreater(len(projected[SESSION_SUMMARY_KEY]), 100)
        self.assertLessEqual(len(projected[SESSION_SUMMARY_KEY]), 1200)
        self.assertIn("memory-24", projected)


if __name__ == "__main__":
    unittest.main()
