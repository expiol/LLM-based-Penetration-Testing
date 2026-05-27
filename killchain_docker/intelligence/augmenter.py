"""High-level intelligence facade.

Exposes a ``context_for(state)`` contract for planner construction, backed by:

- durable memory (already loaded into ``state.cross_run_memory``),
- a relevant-recall selector over that memory,
- optional web retrieval (CVE / ATT&CK / Exploit-DB) gated by knowledge_mode.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from killchain_docker.intelligence.config import (
    DEFAULT_KNOWLEDGE_MODE,
    KNOWLEDGE_MODE_DISABLED,
    KNOWLEDGE_MODE_ENABLED,
    KNOWLEDGE_MODE_OFFLINE,
    default_recall_limit,
    knowledge_mode,
)
from killchain_docker.intelligence.hit import KnowledgeHit
from killchain_docker.intelligence.memdir import RecallQuery, select_records
from killchain_docker.intelligence.status import public_knowledge_payload
from killchain_docker.intelligence.web import WebBudget, WebRetriever
from killchain_docker.llm.gateway import LLMClient
from killchain_docker.logging_utils import get_logger
from killchain_docker.memory.durable import DurableMemoryRecord

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


LOGGER = get_logger(__name__)
_STATE_KEY = "knowledge"
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{4,}")


@dataclass(frozen=True)
class IntelligenceContext:
    """One snapshot of the augmentation result for the current cycle."""

    enabled: bool
    mode: str
    status: str
    hits: list[KnowledgeHit]


class IntelligenceAugmenter:
    """Build the planner-facing knowledge augmentation each cycle."""

    def __init__(
        self,
        *,
        mode: str | None = None,
        memory_root: Path | None = None,
        llm_client: LLMClient | None = None,
        web_retriever: WebRetriever | None = None,
        recall_limit: int | None = None,
    ) -> None:
        self._configured_mode = mode
        self.llm_client = llm_client
        self.memory_root = Path(memory_root) if memory_root is not None else None
        self.web_retriever = web_retriever
        self._recall_limit = recall_limit
        self._web_budget: WebBudget | None = None

    @classmethod
    def from_default(
        cls,
        *,
        mode: str | None = None,
        memory_root: Path | None = None,
        llm_client: LLMClient | None = None,
    ) -> "IntelligenceAugmenter":
        return cls(mode=mode, memory_root=memory_root, llm_client=llm_client)

    @property
    def mode(self) -> str:
        return knowledge_mode(self._configured_mode)

    @property
    def recall_limit(self) -> int:
        return self._recall_limit or default_recall_limit()

    @property
    def enabled(self) -> bool:
        return self.mode != KNOWLEDGE_MODE_DISABLED

    def context_for(self, state: "RunState") -> IntelligenceContext:
        mode = self.mode
        if mode == KNOWLEDGE_MODE_DISABLED:
            self._cache(state, mode=mode, status="disabled", hits=[])
            return IntelligenceContext(enabled=False, mode=mode, status="disabled", hits=[])

        memory_hits = self._memory_hits(state)
        web_hits: list[KnowledgeHit] = []
        if mode == KNOWLEDGE_MODE_ENABLED:
            web_hits = self._web_hits(state)

        merged = list(memory_hits) + list(web_hits)
        status = "hit" if merged else ("miss" if state.cross_run_memory else "empty_query")
        self._cache(state, mode=mode, status=status, hits=merged)
        return IntelligenceContext(
            enabled=True, mode=mode, status=status, hits=merged
        )

    def _memory_hits(self, state: "RunState") -> list[KnowledgeHit]:
        records = list(state.cross_run_memory)
        if not records:
            return []
        query = self._recall_query(state)
        chosen = select_records(
            records,
            query=query,
            limit=self.recall_limit,
            llm_client=self.llm_client,
        )
        return [_record_to_hit(record) for record in chosen]

    def _web_hits(self, state: "RunState") -> list[KnowledgeHit]:
        retriever = self._resolve_web_retriever()
        if retriever is None:
            return []
        challenge_meta = state.metadata.get("challenge", {}) or {}
        category = str(challenge_meta.get("category") or "").strip().lower() or "misc"
        keywords = self._web_keywords(state)
        if not keywords:
            return []
        blocked = self._blocked_tokens(state)
        try:
            return retriever.search(
                query=" ".join(keywords[:6]),
                category=category,
                keywords=keywords,
                blocked_tokens=blocked,
            )
        except Exception:
            LOGGER.exception("web retrieval failed", extra={"category": category})
            return []

    def _resolve_web_retriever(self) -> WebRetriever | None:
        if self.web_retriever is not None:
            return self.web_retriever
        if self.memory_root is None:
            return None
        if self._web_budget is None:
            self._web_budget = WebBudget()
        self.web_retriever = WebRetriever(
            memory_root=self.memory_root,
            budget=self._web_budget,
        )
        return self.web_retriever

    @staticmethod
    def _recall_query(state: "RunState") -> RecallQuery:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        category = str(challenge_meta.get("category") or "").strip().lower() or "misc"
        stalled = ()
        cache = state.metadata.get(_STATE_KEY)
        if isinstance(cache, dict):
            raw_stalled = cache.get("stalled_families")
            if isinstance(raw_stalled, list):
                stalled = tuple(str(item) for item in raw_stalled if str(item))
        keywords = IntelligenceAugmenter._web_keywords(state)
        return RecallQuery(
            objective=state.objective or "",
            category=category,
            keywords=tuple(keywords),
            stalled_families=stalled,
        )

    @staticmethod
    def _web_keywords(state: "RunState") -> tuple[str, ...]:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        category = str(challenge_meta.get("category") or "").strip().lower()
        out: list[str] = []
        if category:
            out.append(category)
        # Use observed artifact extensions and finding titles, never names/ids.
        for finding in list(state.findings.values())[-6:]:
            title = (finding.title or "").strip()
            for token in _TOKEN_RE.findall(title.lower()):
                if token not in out:
                    out.append(token)
        for artifact in list(state.artifacts.values())[-6:]:
            path = (artifact.path or "").strip()
            ext = path.rsplit(".", 1)[-1] if "." in path else ""
            if ext and len(ext) <= 6 and ext not in out:
                out.append(ext.lower())
        objective = (state.objective or "").lower()
        for token in _TOKEN_RE.findall(objective):
            if token not in out:
                out.append(token)
            if len(out) >= 16:
                break
        return tuple(out[:16])

    @staticmethod
    def _blocked_tokens(state: "RunState") -> tuple[str, ...]:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        candidates = (
            challenge_meta.get("name"),
            challenge_meta.get("canonical_name"),
            challenge_meta.get("event"),
            challenge_meta.get("event_key"),
            challenge_meta.get("year"),
        )
        blocked = []
        for candidate in candidates:
            text = str(candidate or "").strip()
            if text:
                blocked.append(text)
        # The expected flag, if present, must never leak.
        validated = state.validated_flag
        if validated:
            blocked.append(str(validated))
        return tuple(blocked)

    @staticmethod
    def _cache(
        state: "RunState",
        *,
        mode: str,
        status: str,
        hits: list[KnowledgeHit],
    ) -> None:
        existing = state.metadata.get(_STATE_KEY)
        cache: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
        cache.update(
            {
                "enabled": mode != KNOWLEDGE_MODE_DISABLED,
                "mode": mode,
                "status": status,
                "hit_count": len(hits),
                "hint_count": len(hits),
            }
        )
        if hits:
            cache["knowledge_hints"] = [hit.to_prompt_dict() for hit in hits]
        else:
            cache.pop("knowledge_hints", None)
        # Surface an audit-safe public projection so callers that read state
        # metadata directly still see consistent values.
        public = public_knowledge_payload(cache) or {}
        cache["public_status"] = public.get("status")
        cache["public_policy"] = public.get("policy")
        state.metadata[_STATE_KEY] = cache


def _record_to_hit(record: DurableMemoryRecord) -> KnowledgeHit:
    title = (record.title or record.key)[:160]
    summary_lines = [line.strip() for line in (record.value or "").splitlines() if line.strip()]
    summary = " ".join(summary_lines)[:280]
    return KnowledgeHit(
        source="memory",
        scope=record.scope.value,
        key=record.key,
        title=title,
        summary=summary,
        value=record.value or "",
        score=0.0,
        extra={
            "category": record.category or "",
        },
    )
