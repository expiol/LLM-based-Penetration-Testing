"""High-level RAG facade.

This module owns the only piece of glue that turns a :class:`GlobalState`
into planner-ready writeup hints: build a query from challenge metadata,
run :class:`KnowledgeRetriever`, and shape the hits into compact dicts for
the planner prompt.

Centralizing the logic here keeps a few rules consistent across callers:

* exactly one place builds the retrieval query (so swapping fields like
  ``description`` / ``files`` happens in one spot);
* exactly one place applies the self-exclusion / strict-event-exclusion
  policy controlled by ``AUTOPENTEST_RAG_STRICT_EXCLUDE``;
* the per-state top-1 score is cached on ``state.metadata["rag"]`` so
  downstream consumers can inspect the last retrieval signal without
  knowing retriever internals.

Callers that already hold a :class:`KnowledgeRetriever` (tests, unusual
embedding setups) construct the augmenter with that retriever directly.
The default constructor :meth:`from_default` uses the module-level
singleton, which itself returns ``None`` when fastembed isn't installed
or the dataset is missing — in that case ``augment`` simply returns
``[]`` and every consumer degrades gracefully.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from killchain_docker.knowledge.retriever import (
    KnowledgeRetriever,
    RetrievalHit,
    default_top_k,
    get_retriever,
    strict_event_exclusion_enabled,
)
from killchain_docker.state import GlobalState


PLANNER_SOLUTION_CHARS = 1500
PLANNER_DESCRIPTION_CHARS = 280
PLANNER_FILES = 8

# Cap the number of hits we ever feed to a single prompt.  Three is a
# reasonable upper bound: the dense retriever's recall@3 on the dev set
# is already over 0.9 for in-corpus queries, and beyond that we just
# spend tokens on lower-confidence noise.
MAX_HITS = 3

# Snapshot key on ``state.metadata`` where the augmenter caches its last
# call.  See :meth:`_cache_run_result`.
_STATE_RAG_KEY = "rag"


@dataclass(frozen=True)
class RagHit:
    """Typed writeup hit used by planner prompt injection."""

    challenge_id: str
    name: str
    category: str
    year: str
    event: str
    description: str
    files: list[str]
    solution_sketch: str
    score: float

    @classmethod
    def from_retrieval(cls, hit: RetrievalHit) -> "RagHit":
        return cls(
            challenge_id=hit.challenge_id,
            name=hit.name,
            category=hit.category,
            year=hit.year,
            event=hit.event,
            description=hit.description,
            files=list(hit.files),
            solution_sketch=hit.solution_sketch,
            score=float(hit.score),
        )

    def to_prompt_dict(
        self,
        *,
        max_solution_chars: int,
        max_description_chars: int,
        max_files: int,
    ) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "name": self.name,
            "category": self.category,
            "year": self.year,
            "event": self.event,
            "description": self.description[:max_description_chars],
            "files": self.files[:max_files],
            "solution_sketch": self.solution_sketch[:max_solution_chars],
            "score": round(float(self.score), 4),
        }


@dataclass(frozen=True)
class RagContext:
    """One retrieval snapshot for the current run."""

    enabled: bool
    top_score: float = 0.0
    top_challenge_id: str | None = None
    exact_self_hit: bool = False
    hits: list[RagHit] | None = None

    @property
    def high_confidence(self) -> bool:
        from killchain_docker.prompts.rag import HIGH_CONFIDENCE_SCORE

        return self.top_score >= HIGH_CONFIDENCE_SCORE

    def prompt_hits(
        self,
        *,
        max_solution_chars: int,
        max_description_chars: int,
        max_files: int,
    ) -> list[dict[str, Any]]:
        return [
            hit.to_prompt_dict(
                max_solution_chars=max_solution_chars,
                max_description_chars=max_description_chars,
                max_files=max_files,
            )
            for hit in list(self.hits or [])
        ]


class KnowledgeAugmenter:
    """Build top-k writeup hints for prompt injection.

    Holds an optional :class:`KnowledgeRetriever`; when it's ``None`` (RAG
    disabled, dataset missing, fastembed not installed) every method
    returns the empty result so callers can ignore the failure mode.
    """

    def __init__(
        self,
        retriever: KnowledgeRetriever | None,
        *,
        top_k: int | None = None,
    ) -> None:
        self.retriever = retriever
        self._configured_top_k = top_k

    # ------------------------------------------------------------------
    # Construction helpers
    # ------------------------------------------------------------------

    @classmethod
    def from_default(cls) -> "KnowledgeAugmenter":
        """Build using the process-wide retriever singleton.

        Returns an augmenter that no-ops when the singleton is unavailable
        (fastembed not installed, dataset missing, ``AUTOPENTEST_RAG_DISABLED``
        set, etc.).  Callers should treat ``KnowledgeAugmenter.enabled``
        as the gate before bothering to call any of the other methods.
        """
        return cls(get_retriever())

    @property
    def enabled(self) -> bool:
        """``True`` when a non-empty retriever is wired up."""
        return self.retriever is not None and len(self.retriever) > 0

    @property
    def top_k(self) -> int:
        """Resolved top-k honoring env overrides + the hard cap."""
        configured = self._configured_top_k or default_top_k()
        return max(1, min(configured, MAX_HITS))

    # ------------------------------------------------------------------
    # Primary entry points
    # ------------------------------------------------------------------

    def for_planner(self, state: GlobalState) -> list[dict[str, Any]]:
        """Render hits with the planner-side per-field budget."""
        return self.context_for(state).prompt_hits(
            max_solution_chars=PLANNER_SOLUTION_CHARS,
            max_description_chars=PLANNER_DESCRIPTION_CHARS,
            max_files=PLANNER_FILES,
        )

    def context_for(self, state: GlobalState) -> RagContext:
        """Return typed retrieval context for the run.

        This is the single RAG integration point. The planner renders
        prompt-shaped dicts from this typed context.
        """
        if not self.enabled:
            return RagContext(enabled=False, hits=[])
        category = self._infer_category(state)
        query = self._build_query(state, category)
        if not query:
            return RagContext(enabled=True, hits=[])
        excluded_ids, excluded_events = self._exclusion_keys(state)

        try:
            assert self.retriever is not None
            raw_hits = self.retriever.retrieve(
                query,
                category=category,
                top_k=self.top_k,
                exclude_challenge_ids=excluded_ids,
                exclude_event_keys=excluded_events,
                require_solution_sketch=True,
            )
        except Exception:
            return RagContext(enabled=True, hits=[])

        hits = [RagHit.from_retrieval(hit) for hit in raw_hits]
        self._cache_run_result(state, raw_hits)
        canonical_id = str(
            (state.metadata.get("challenge", {}) or {}).get("canonical_name") or ""
        ).strip()
        top_hit = hits[0] if hits else None
        return RagContext(
            enabled=True,
            top_score=float(top_hit.score) if top_hit else 0.0,
            top_challenge_id=top_hit.challenge_id if top_hit else None,
            exact_self_hit=bool(top_hit and canonical_id and top_hit.challenge_id == canonical_id),
            hits=hits,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    @staticmethod
    def _infer_category(state: GlobalState) -> str:
        return str(
            state.metadata.get("challenge", {}).get("category") or "misc"
        ).lower()

    @staticmethod
    def _build_query(state: GlobalState, category: str) -> str:
        """Compose the dense retrieval query.

        We weight the most distinctive fields first (name + category) so
        that even when ``description`` is generic ("Find the flag.") the
        retriever still has a strong signal.  ``files`` is a great
        discriminator in practice — both ``stfu`` and ``flag.stfu`` show
        up only on one challenge in the dev split.
        """
        challenge_meta = state.metadata.get("challenge", {}) or {}
        name = str(challenge_meta.get("name") or "").strip()
        description = (state.objective or "").strip()
        files = challenge_meta.get("files") or []
        files_part = ", ".join(str(f) for f in files[:6])

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
    def _exclusion_keys(
        state: GlobalState,
    ) -> tuple[list[str], list[tuple[str, str]]]:
        """Honor the strict-exclude env var.

        The default policy is "no self-exclusion": the retriever may
        surface the current challenge's own writeup, which is the
        "upper-bound oracle" setting the user explicitly chose.  Setting
        ``AUTOPENTEST_RAG_STRICT_EXCLUDE=1`` flips back to the
        conservative behaviour where same-id and same-(year, event) hits
        are filtered out so the hint can't trivially leak the live
        challenge's solution.
        """
        if not strict_event_exclusion_enabled():
            return [], []

        challenge_meta = state.metadata.get("challenge", {}) or {}
        canonical_id = str(challenge_meta.get("canonical_name") or "").strip()
        challenge_year = str(challenge_meta.get("year") or "").strip()
        challenge_event = str(challenge_meta.get("event") or "").strip()
        excluded_ids: list[str] = [canonical_id] if canonical_id else []
        excluded_events: list[tuple[str, str]] = (
            [(challenge_year, challenge_event)]
            if challenge_year and challenge_event
            else []
        )
        return excluded_ids, excluded_events

    # ----------------------- cache helpers ----------------------------

    @staticmethod
    def _cache_run_result(
        state: GlobalState,
        hits: list[RetrievalHit],
    ) -> None:
        """Store top score + top-1 challenge id on ``state.metadata['rag']``.

        Only the cheap signals are cached; the rendered hit body lives
        wherever the calling prompt builder put it. We cache only what other components need
        without re-running retrieval.
        """
        cache: dict[str, Any] = {
            "top_score": float(hits[0].score) if hits else 0.0,
            "top_challenge_id": hits[0].challenge_id if hits else None,
            "hit_count": len(hits),
        }
        state.metadata[_STATE_RAG_KEY] = cache
