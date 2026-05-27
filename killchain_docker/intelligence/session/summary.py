"""Per-run session summary writer.

Writes a compact summary into ``RunState.run_memory`` under a reserved key so
later planner cycles can see "what we already learned" without re-reading the
full execution log. The summary itself is generated cheaply from the existing
report projection (no extra LLM call) — claude-code uses a forked subagent
because it's summarising a chat transcript; we already have a structured run
state, so we project it directly.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.intelligence.session.thresholds import (
    DEFAULT_THRESHOLDS,
    SessionSummaryThresholds,
)

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


SESSION_SUMMARY_KEY = "__session_summary__"


def maybe_refresh_session_summary(
    state: "RunState",
    *,
    cycle: int,
    thresholds: SessionSummaryThresholds = DEFAULT_THRESHOLDS,
) -> bool:
    """Refresh ``state.run_memory[SESSION_SUMMARY_KEY]`` when thresholds met."""

    if cycle < thresholds.minimum_cycles_to_init:
        return False
    last_cycle = state.metadata.get("session_summary_cycle")
    if isinstance(last_cycle, int) and (
        cycle - last_cycle < thresholds.minimum_cycles_between_updates
    ):
        return False

    summary = _render_summary(state)
    if not summary:
        return False
    state.run_memory[SESSION_SUMMARY_KEY] = summary
    state.metadata["session_summary_cycle"] = cycle
    return True


def _render_summary(state: "RunState") -> str:
    """Project run state into a short markdown summary."""

    lines: list[str] = []
    objective = (state.objective or "").strip()
    if objective:
        lines.append(f"objective: {objective[:240]}")

    rounds = len(state.rounds)
    todos = len(state.todos)
    open_todos = sum(
        1
        for todo in state.todos
        if str(getattr(todo, "status", "")).lower() in {"pending", "running"}
    )
    flag_candidates = len(state.flag_candidates)
    findings = len(state.findings)
    evidence = len(state.evidence)
    lines.append(
        " | ".join(
            (
                f"rounds={rounds}",
                f"todos={todos}",
                f"open={open_todos}",
                f"findings={findings}",
                f"evidence={evidence}",
                f"flag_candidates={flag_candidates}",
            )
        )
    )

    last_round = state.rounds[-1] if state.rounds else None
    if last_round is not None:
        summary_text = getattr(last_round.summary, "summary", "") or ""
        if summary_text:
            lines.append(f"last_round_summary: {summary_text[:300]}")

    last_execution = state.execution_log[-1] if state.execution_log else None
    if last_execution is not None:
        summary_text = getattr(last_execution, "summary", "") or ""
        if summary_text:
            lines.append(f"last_step: {summary_text[:240]}")

    return "\n".join(line for line in lines if line)
