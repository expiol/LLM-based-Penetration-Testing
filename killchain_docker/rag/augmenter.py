"""High-level RAG facade over a replaceable provider."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from killchain_docker.knowledge.embedder import EmbeddingUnavailable
from killchain_docker.logging_utils import get_logger
from killchain_docker.rag.config import (
    RAG_MODE_DISABLED,
    RAG_MODE_STRICT,
    default_top_k,
    rag_mode,
)
from killchain_docker.rag.factory import build_default_provider
from killchain_docker.rag.hit import RetrievalHit, event_key
from killchain_docker.rag.providers import RagProvider
from killchain_docker.rag.status import public_rag_payload
from killchain_docker.state.run_state import RunState


LOGGER = get_logger(__name__)
PLANNER_SOLUTION_CHARS = 9000
PLANNER_DESCRIPTION_CHARS = 280
PLANNER_DESCRIPTION_ONLY_CHARS = 1200
PLANNER_FILES = 8
MAX_HITS = 3
_STATE_RAG_KEY = "rag"


@dataclass(frozen=True)
class RagContext:
    """One retrieval snapshot for the current run."""

    enabled: bool
    mode: str = "oracle"
    status: str = "unavailable"
    top_score: float = 0.0
    top_challenge_id: str | None = None
    challenge_identity_hit: bool = False
    hits: list[RetrievalHit] | None = None

    def prompt_hits(
        self, *, max_solution_chars: int, max_description_chars: int, max_files: int
    ) -> list[dict[str, Any]]:
        rendered: list[dict[str, Any]] = []
        for rank, hit in enumerate(list(self.hits or []), start=1):
            rendered.append(
                _prompt_hit_dict(
                    hit,
                    rank=rank,
                    max_solution_chars=max_solution_chars,
                    max_description_chars=max_description_chars,
                    max_files=max_files,
                )
            )
        return rendered


class RagAugmenter:
    """Resolve retrieval context and cache public run metadata."""

    def __init__(
        self,
        provider: RagProvider | None,
        *,
        top_k: int | None = None,
        mode: str | None = None,
    ) -> None:
        self.provider = provider
        self._configured_top_k = top_k
        self._configured_mode = mode

    @classmethod
    def from_default(cls, *, mode: str | None = None) -> "RagAugmenter":
        """Build using the configured default provider."""

        return cls(build_default_provider(mode=mode), mode=mode)

    @property
    def mode(self) -> str:
        return rag_mode(self._configured_mode)

    @property
    def enabled(self) -> bool:
        """``True`` when a non-empty provider is wired up."""

        return self.provider is not None and len(self.provider) > 0

    @property
    def top_k(self) -> int:
        """Resolved top-k honoring env overrides and the hard cap."""

        configured = self._configured_top_k or default_top_k()
        return max(1, min(configured, MAX_HITS))

    def for_planner(self, state: RunState) -> list[dict[str, Any]]:
        """Return redacted, provenance-free method hints for planner context."""

        return self.context_for(state).prompt_hits(
            max_solution_chars=PLANNER_SOLUTION_CHARS,
            max_description_chars=PLANNER_DESCRIPTION_CHARS,
            max_files=PLANNER_FILES,
        )

    def context_for(self, state: RunState) -> RagContext:
        """Return typed retrieval context for the run."""

        mode = self.mode
        if mode == RAG_MODE_DISABLED:
            self._cache_run_result(
                state, [], enabled=False, mode=mode, status="disabled"
            )
            self._log_context_result(state, mode=mode, category=None, query="", top_k=0)
            return RagContext(enabled=False, mode=mode, status="disabled", hits=[])
        if not self.enabled:
            self._cache_run_result(
                state, [], enabled=False, mode=mode, status="unavailable"
            )
            self._log_context_result(state, mode=mode, category=None, query="", top_k=0)
            return RagContext(enabled=False, mode=mode, status="unavailable", hits=[])

        category = self._infer_category(state)
        query = self._build_query(state, category)
        if not query:
            self._cache_run_result(
                state, [], enabled=True, mode=mode, status="empty_query"
            )
            self._log_context_result(
                state, mode=mode, category=category, query=query, top_k=self.top_k
            )
            return RagContext(enabled=True, mode=mode, status="empty_query", hits=[])

        excluded_ids, excluded_events = self._exclusion_keys(state, mode)
        try:
            assert self.provider is not None
            raw_hits = self.provider.retrieve(
                query,
                category=category,
                top_k=self.top_k,
                exclude_challenge_ids=excluded_ids,
                exclude_event_keys=excluded_events,
                require_solution_sketch=True,
            )
        except EmbeddingUnavailable:
            LOGGER.warning(
                "RAG disabled because embedding backend is unavailable",
                exc_info=True,
                extra={"rag_mode": mode, "category": category, "top_k": self.top_k},
            )
            self.provider = None
            self._cache_run_result(
                state, [], enabled=False, mode=mode, status="unavailable"
            )
            self._log_context_result(
                state, mode=mode, category=category, query=query, top_k=self.top_k
            )
            return RagContext(enabled=False, mode=mode, status="unavailable", hits=[])
        except Exception:
            LOGGER.exception(
                "RAG retrieval failed", extra={"rag_mode": mode, "category": category}
            )
            self._cache_run_result(state, [], enabled=True, mode=mode, status="error")
            self._log_context_result(
                state, mode=mode, category=category, query=query, top_k=self.top_k
            )
            return RagContext(enabled=True, mode=mode, status="error", hits=[])

        identity_hit = self._direct_identity_hit(
            state, mode, require_solution_sketch=False
        )
        identity_solution_hit = (
            identity_hit
            if identity_hit is not None and identity_hit.solution_sketch.strip()
            else None
        )
        ranked_hits = self._ranked_hits_with_identity(
            raw_hits, state, mode, identity_solution_hit
        )
        metadata_only_identity = (
            mode != RAG_MODE_STRICT
            and identity_hit is not None
            and (identity_solution_hit is None)
        )
        hits = (
            []
            if metadata_only_identity
            else self._select_prompt_hits(ranked_hits, state, mode)
        )
        canonical_id = str(
            (state.metadata.get("challenge", {}) or {}).get("canonical_name") or ""
        ).strip()
        top_hit = hits[0] if hits else None
        challenge_identity_hit = bool(
            top_hit and canonical_id and (top_hit.challenge_id == canonical_id)
        )
        status = (
            "metadata_only" if metadata_only_identity else "hit" if hits else "miss"
        )
        self._cache_run_result(
            state,
            [identity_hit, *ranked_hits]
            if metadata_only_identity and identity_hit
            else ranked_hits,
            enabled=True,
            mode=mode,
            status=status,
            challenge_identity_hit=challenge_identity_hit,
            prompt_hits=hits,
            retrieved_hit_count=len(raw_hits),
            excluded_challenge_ids=excluded_ids,
            excluded_event_keys=excluded_events,
        )
        self._log_context_result(
            state, mode=mode, category=category, query=query, top_k=self.top_k
        )
        return RagContext(
            enabled=True,
            mode=mode,
            status=status,
            top_score=float(top_hit.score) if top_hit else 0.0,
            top_challenge_id=top_hit.challenge_id if top_hit else None,
            challenge_identity_hit=challenge_identity_hit,
            hits=hits,
        )

    @staticmethod
    def _infer_category(state: RunState) -> str:
        return str(
            state.metadata.get("challenge", {}).get("category") or "misc"
        ).lower()

    @staticmethod
    def _build_query(state: RunState, category: str) -> str:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        name = str(challenge_meta.get("name") or "").strip()
        description = (state.objective or "").strip()
        files = challenge_meta.get("files") or []
        files_part = ", ".join((str(f) for f in files[:6]))
        parts: list[str] = []
        if name:
            parts.append(f"name: {name}")
        if category:
            parts.append(f"category: {category}")
        if description:
            parts.append(f"description: {description[:600]}")
        if files_part:
            parts.append(f"files: {files_part}")
        return "\n".join(parts).strip()

    @staticmethod
    def _exclusion_keys(state: RunState, mode: str) -> tuple[list[str], list[str]]:
        if mode != RAG_MODE_STRICT:
            return ([], [])
        challenge_meta = state.metadata.get("challenge", {}) or {}
        canonical_id = str(challenge_meta.get("canonical_name") or "").strip()
        challenge_year = str(challenge_meta.get("year") or "").strip()
        challenge_event = str(challenge_meta.get("event") or "").strip()
        challenge_event_key = str(challenge_meta.get("event_key") or "").strip().lower()
        if not challenge_event_key:
            challenge_event_key = event_key(challenge_year, challenge_event)
        excluded_ids: list[str] = [canonical_id] if canonical_id else []
        excluded_events: list[str] = (
            [challenge_event_key] if challenge_event_key else []
        )
        return (excluded_ids, excluded_events)

    @staticmethod
    def _select_prompt_hits(
        hits: list[RetrievalHit], state: RunState, mode: str
    ) -> list[RetrievalHit]:
        if mode == RAG_MODE_STRICT:
            return hits
        canonical_id = str(
            (state.metadata.get("challenge", {}) or {}).get("canonical_name") or ""
        ).strip()
        if not canonical_id:
            return hits
        identity_hits = [hit for hit in hits if hit.challenge_id == canonical_id]
        return identity_hits or hits

    def _ranked_hits_with_identity(
        self,
        hits: list[RetrievalHit],
        state: RunState,
        mode: str,
        identity_hit: RetrievalHit | None = None,
    ) -> list[RetrievalHit]:
        if mode == RAG_MODE_STRICT:
            return hits
        direct = identity_hit or self._direct_identity_hit(
            state, mode, require_solution_sketch=True
        )
        if direct is None:
            return hits
        return [
            direct,
            *[hit for hit in hits if hit.challenge_id != direct.challenge_id],
        ]

    def _direct_identity_hit(
        self, state: RunState, mode: str, *, require_solution_sketch: bool
    ) -> RetrievalHit | None:
        if mode == RAG_MODE_STRICT or self.provider is None:
            return None
        canonical_id = str(
            (state.metadata.get("challenge", {}) or {}).get("canonical_name") or ""
        ).strip()
        return self.provider.hit_by_challenge_id(
            canonical_id, require_solution_sketch=require_solution_sketch
        )

    @staticmethod
    def _log_context_result(
        state: RunState, *, mode: str, category: str | None, query: str, top_k: int
    ) -> None:
        cache = state.metadata.get(_STATE_RAG_KEY)
        if not isinstance(cache, dict):
            return
        public = public_rag_payload(cache) or {}
        LOGGER.info(
            "RAG context resolved",
            extra={
                "rag_mode": mode,
                "rag_enabled": bool(public.get("enabled")),
                "rag_status": public.get("status"),
                "rag_policy": public.get("policy"),
                "hint_count": int(public.get("hint_count") or 0),
                "retrieved_hit_count": int(cache.get("retrieved_hit_count") or 0),
                "excluded_challenge_count": len(
                    cache.get("excluded_challenge_ids") or []
                ),
                "excluded_event_count": len(cache.get("excluded_event_keys") or []),
                "category": category or "",
                "query_chars": len(query or ""),
                "top_k": top_k,
            },
        )

    @staticmethod
    def _cache_run_result(
        state: RunState,
        hits: list[RetrievalHit],
        *,
        enabled: bool = True,
        mode: str,
        status: str,
        challenge_identity_hit: bool = False,
        prompt_hits: list[RetrievalHit] | None = None,
        retrieved_hit_count: int | None = None,
        excluded_challenge_ids: list[str] | None = None,
        excluded_event_keys: list[str] | None = None,
    ) -> None:
        existing = state.metadata.get(_STATE_RAG_KEY)
        cache: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
        cache.pop("related_writeups", None)
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_year = str(challenge_meta.get("year") or "").strip()
        challenge_event = str(challenge_meta.get("event") or "").strip()
        challenge_event_key = str(challenge_meta.get("event_key") or "").strip().lower()
        if not challenge_event_key:
            challenge_event_key = event_key(challenge_year, challenge_event)
        prompt_hits = list(prompt_hits if prompt_hits is not None else hits)
        knowledge_hints = [
            _prompt_hit_dict(
                hit,
                rank=rank,
                max_solution_chars=PLANNER_SOLUTION_CHARS,
                max_description_chars=PLANNER_DESCRIPTION_CHARS,
                max_files=PLANNER_FILES,
            )
            for rank, hit in enumerate(prompt_hits, start=1)
        ]
        cache.update(
            {
                "enabled": enabled,
                "mode": mode,
                "strict_exclude": mode == RAG_MODE_STRICT,
                "status": status,
                "top_score": float(prompt_hits[0].score) if prompt_hits else 0.0,
                "top_challenge_id": prompt_hits[0].challenge_id
                if prompt_hits
                else None,
                "top_year": prompt_hits[0].year if prompt_hits else None,
                "top_event": prompt_hits[0].event if prompt_hits else None,
                "top_event_key": prompt_hits[0].event_key if prompt_hits else None,
                "hit_count": len(prompt_hits),
                "retrieved_hit_count": len(hits)
                if retrieved_hit_count is None
                else retrieved_hit_count,
                "challenge_identity_hit": challenge_identity_hit,
                "challenge_event_key": challenge_event_key or None,
                "excluded_challenge_ids": list(excluded_challenge_ids or []),
                "excluded_event_keys": list(excluded_event_keys or []),
                "hit_provenance": [_hit_provenance(hit) for hit in hits],
                "hint_count": len(prompt_hits),
            }
        )
        if knowledge_hints:
            cache["knowledge_hints"] = knowledge_hints
        else:
            cache.pop("knowledge_hints", None)
        state.metadata[_STATE_RAG_KEY] = cache


def _prompt_hit_dict(
    hit: RetrievalHit,
    *,
    rank: int,
    max_solution_chars: int,
    max_description_chars: int,
    max_files: int,
) -> dict[str, Any]:
    description_chars = max_description_chars
    if not hit.solution_sketch.strip():
        description_chars = max(description_chars, PLANNER_DESCRIPTION_ONLY_CHARS)
    item = hit.to_prompt_dict(max_solution_chars, description_chars, max_files)
    return {
        "rank": rank,
        "category": item["category"],
        "description": item["description"],
        "files": item["files"],
        "solution_sketch": item["solution_sketch"],
    }


def _hit_provenance(hit: RetrievalHit) -> dict[str, Any]:
    return {
        "challenge_id": hit.challenge_id,
        "year": hit.year,
        "event": hit.event,
        "event_key": hit.event_key,
        "score": round(float(hit.score), 4),
    }

