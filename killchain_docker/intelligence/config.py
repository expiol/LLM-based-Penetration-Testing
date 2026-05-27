"""Knowledge mode configuration.

Modes describe whether the intelligence aggregator may consult external
sources:

- ``disabled``: no knowledge_augmentation is produced.
- ``offline``: durable memory + relevant recall only. Default for benchmark
  reproducibility and airgapped operation.
- ``enabled``: ``offline`` plus opt-in web retrieval (CVE/ATT&CK/Exploit-DB).
"""

from __future__ import annotations

import os


KNOWLEDGE_MODE_ENV = "AUTOPENTEST_KNOWLEDGE_MODE"
KNOWLEDGE_MODE_DISABLED = "disabled"
KNOWLEDGE_MODE_OFFLINE = "offline"
KNOWLEDGE_MODE_ENABLED = "enabled"
KNOWLEDGE_MODES = frozenset(
    {KNOWLEDGE_MODE_DISABLED, KNOWLEDGE_MODE_OFFLINE, KNOWLEDGE_MODE_ENABLED}
)
DEFAULT_KNOWLEDGE_MODE = KNOWLEDGE_MODE_OFFLINE


def knowledge_mode(override: str | None = None) -> str:
    """Return the active knowledge mode."""

    raw = (override if override is not None else os.getenv(KNOWLEDGE_MODE_ENV) or "")
    raw = str(raw).strip().lower()
    if raw in KNOWLEDGE_MODES:
        return raw
    if raw:
        choices = ", ".join(sorted(KNOWLEDGE_MODES))
        raise ValueError(
            f"unknown knowledge mode {raw!r}; expected one of: {choices}"
        )
    return DEFAULT_KNOWLEDGE_MODE


def default_recall_limit() -> int:
    raw = (os.getenv("AUTOPENTEST_KNOWLEDGE_RECALL") or "").strip()
    if not raw:
        return 5
    try:
        value = int(raw)
    except ValueError:
        return 5
    return max(1, min(value, 8))
