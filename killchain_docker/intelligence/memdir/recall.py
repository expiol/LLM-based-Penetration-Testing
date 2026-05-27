"""Lightweight relevant-recall selector over durable memory records.

Mirrors claude-code's ``findRelevantMemories``: scan file heads, ask a
small structured-output LLM to pick a few slugs, fall back to a deterministic
scorer when the LLM is unavailable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from killchain_docker.intelligence.memdir.manifest import (
    MemoryManifestEntry,
    build_manifest,
)
from killchain_docker.llm.gateway import LLMClient, LLMClientError
from killchain_docker.logging_utils import get_logger
from killchain_docker.memory.durable import DurableMemoryRecord, DurableMemoryScope


LOGGER = get_logger(__name__)
_SCOPE_PRIORITY = {
    DurableMemoryScope.CATEGORY.value: 2,
    DurableMemoryScope.GLOBAL.value: 1,
}
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{3,}")
_DELEGATE_THRESHOLD = 6  # below this, deterministic scoring is enough


class _RecallDecision(BaseModel):
    """Selector schema: pick up to ``limit`` slugs by relevance."""

    model_config = ConfigDict(extra="ignore")

    selected_slugs: list[str] = Field(default_factory=list)
    rationale: str = ""


@dataclass(frozen=True)
class RecallQuery:
    """Inputs the selector uses to weigh relevance."""

    objective: str
    category: str
    keywords: tuple[str, ...] = ()
    stalled_families: tuple[str, ...] = ()


def select_records(
    records: list[DurableMemoryRecord],
    *,
    query: RecallQuery,
    limit: int,
    llm_client: LLMClient | None = None,
) -> list[DurableMemoryRecord]:
    """Return up to ``limit`` records ordered by relevance to ``query``."""

    if not records or limit <= 0:
        return []
    manifest = build_manifest(records)
    by_slug = {record.slug: record for record in records}

    if llm_client is not None and len(manifest) >= _DELEGATE_THRESHOLD:
        chosen = _llm_select(manifest, query=query, limit=limit, llm=llm_client)
        if chosen:
            picked = [by_slug[slug] for slug in chosen if slug in by_slug]
            if picked:
                return picked[:limit]

    return _deterministic_select(records, query=query, limit=limit)


def _llm_select(
    manifest: list[MemoryManifestEntry],
    *,
    query: RecallQuery,
    limit: int,
    llm: LLMClient,
) -> list[str]:
    snapshot: dict[str, Any] = {
        "objective": (query.objective or "")[:600],
        "category": query.category or "",
        "stalled_families": list(query.stalled_families),
        "candidates": [entry.to_dict() for entry in manifest],
        "instruction": (
            f"Pick up to {limit} slugs whose head most directly informs the next "
            "planner cycle. Prefer entries whose head touches the current "
            "challenge category and observed stagnation. Return slugs only; "
            "never invent slugs that are not in candidates."
        ),
    }
    system_prompt = (
        "You are a memory recall selector. Given a candidate manifest of past "
        "lessons, choose the few that most usefully inform the current planning "
        "step. Return only JSON matching _RecallDecision."
    )
    try:
        decision = llm.generate_json(
            system_prompt=system_prompt,
            user_prompt=_render_user_prompt(snapshot),
            schema=_RecallDecision,
            temperature=0.0,
        )
    except LLMClientError:
        LOGGER.info(
            "knowledge recall selector unavailable; using deterministic fallback",
            exc_info=False,
        )
        return []
    available = {entry.slug for entry in manifest}
    return [slug for slug in decision.selected_slugs if slug in available][:limit]


def _render_user_prompt(snapshot: dict[str, Any]) -> str:
    import json

    return json.dumps(snapshot, ensure_ascii=True, indent=2)


def _deterministic_select(
    records: list[DurableMemoryRecord],
    *,
    query: RecallQuery,
    limit: int,
) -> list[DurableMemoryRecord]:
    keywords = _keywords(query)
    scored: list[tuple[float, int, DurableMemoryRecord]] = []
    for index, record in enumerate(records):
        scope_weight = _SCOPE_PRIORITY.get(record.scope.value, 0)
        text = " ".join(
            (
                record.title or "",
                record.key or "",
                (record.value or "")[:600],
            )
        )
        overlap = _overlap(text, keywords)
        recency_tiebreak = -index
        scored.append(
            (scope_weight + overlap, recency_tiebreak, record)
        )
    scored.sort(key=lambda triple: (triple[0], triple[1]), reverse=True)
    return [record for _, _, record in scored[:limit]]


def _keywords(query: RecallQuery) -> tuple[str, ...]:
    parts: list[str] = []
    if query.category:
        parts.append(query.category)
    if query.objective:
        parts.append(query.objective)
    parts.extend(query.keywords)
    parts.extend(query.stalled_families)
    text = " ".join(parts).lower()
    seen: list[str] = []
    for token in _TOKEN_RE.findall(text):
        if token not in seen:
            seen.append(token)
    return tuple(seen[:32])


def _overlap(text: str, keywords: tuple[str, ...]) -> float:
    if not keywords:
        return 0.0
    lowered = text.lower()
    return sum(1 for keyword in keywords if keyword in lowered)
