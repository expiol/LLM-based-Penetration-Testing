"""Knowledge hit model for the unified intelligence layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


_VALUE_PROMPT_CHARS = 1500
_SUMMARY_PROMPT_CHARS = 280


@dataclass(frozen=True)
class KnowledgeHit:
    """One ranked knowledge item rendered into planner context."""

    source: str  # e.g. "memory", "web/nvd", "web/mitre", "web/exploitdb"
    scope: str  # "global" / "category" / "challenge" / "" for web hits
    key: str
    title: str
    summary: str  # short headline / description
    value: str  # full-text body, capped at write time
    score: float = 0.0
    extra: dict[str, Any] | None = None

    def to_prompt_dict(
        self,
        *,
        max_value_chars: int = _VALUE_PROMPT_CHARS,
        max_summary_chars: int = _SUMMARY_PROMPT_CHARS,
    ) -> dict[str, Any]:
        return {
            "source": self.source,
            "scope": self.scope,
            "key": self.key,
            "title": self.title[: max_summary_chars * 2] if self.title else self.key,
            "summary": (self.summary or "")[:max_summary_chars],
            "value_excerpt": (self.value or "")[:max_value_chars],
        }
