"""Shared result-quality labels used to judge progress."""

from __future__ import annotations

NO_PROGRESS_QUALITIES = frozenset(
    {
        "connection_refused",
        "connection_reset",
        "empty_result",
        "metadata_validation",
        "network_incomplete_read",
        "network_pipe_closed",
        "no_candidate",
        "package_install_blocked",
        "partial_no_candidate",
        "scope_violation_blocked",
        "timeout",
        "unbounded_loop_guard",
    }
)

NEAR_MISS_QUALITIES = frozenset({"near_miss"})
