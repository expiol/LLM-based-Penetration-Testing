"""Session-summary thresholds for long-running orchestrator loops.

Mirrors claude-code's ``sessionMemoryUtils`` thresholds: don't initialise
session-memory until the conversation has grown past a floor, then update
sparingly so we don't burn tokens on incremental summaries.

We adapt the original message-token-based gate to the killchain runtime, where
"work" is measured in productive cycles + worker LLM calls rather than chat
messages.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SessionSummaryThresholds:
    """Conditions that gate writing the in-run session summary."""

    minimum_cycles_to_init: int = 3
    minimum_cycles_between_updates: int = 2
    minimum_tool_calls_between_updates: int = 8


DEFAULT_THRESHOLDS = SessionSummaryThresholds()
