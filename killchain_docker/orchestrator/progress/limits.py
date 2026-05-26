"""Planner progress gate thresholds."""

from __future__ import annotations

FAILURE_COOLDOWN_THRESHOLD = 3
MAX_FAMILY_ATTEMPTS = 10
MAX_FLAG_VALIDATION_ATTEMPTS = 3
CONSECUTIVE_FAILURE_CAP = 5

UNCAPPED_FAMILIES = frozenset(
    {
        "algorithm-verification",
        "artifact-inventory",
        "flag-recovery",
        "recon",
        "crypto-decrypt",
        "binary-analysis",
    }
)
