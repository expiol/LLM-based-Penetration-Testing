"""High-level RAG facade.

This module owns the only piece of glue that turns a :class:`GlobalState`
into prompt-ready writeup hints: build a query from challenge metadata,
run :class:`KnowledgeRetriever`, and shape the hits into compact dicts that
both planner and solver inject into their LLM prompts.

Centralizing the logic here keeps a few rules consistent across callers:

* exactly one place builds the retrieval query (so swapping fields like
  ``description`` / ``files`` happens in one spot);
* exactly one place applies the self-exclusion / strict-event-exclusion
  policy controlled by ``AUTOPENTEST_RAG_STRICT_EXCLUDE``;
* the per-state top-1 score is cached on ``state.metadata["rag"]`` so
  downstream consumers (dispatch policy in particular) can read it
  cheaply without re-running the retriever every cycle.

Callers that already hold a :class:`KnowledgeRetriever` (tests, unusual
embedding setups) construct the augmenter with that retriever directly.
The default constructor :meth:`from_default` uses the module-level
singleton, which itself returns ``None`` when fastembed isn't installed
or the dataset is missing — in that case ``augment`` simply returns
``[]`` and every consumer degrades gracefully.
"""

from __future__ import annotations

from typing import Any

from nyuctf_mutil_killchain.knowledge.retriever import (
    KnowledgeRetriever,
    RetrievalHit,
    default_top_k,
    get_retriever,
    strict_event_exclusion_enabled,
)
from nyuctf_mutil_killchain.state import GlobalState


# Per-hit budgets shared by every consumer.  Solver gets a more generous
# solution_sketch budget than the planner because solvers actually need
# the algorithm body, while planners only need enough to bias the next
# task title.
PLANNER_SOLUTION_CHARS = 1500
PLANNER_DESCRIPTION_CHARS = 280
PLANNER_FILES = 8

SOLVER_SOLUTION_CHARS = 2400
SOLVER_DESCRIPTION_CHARS = 320
SOLVER_FILES = 8

# Cap the number of hits we ever feed to a single prompt.  Three is a
# reasonable upper bound: the dense retriever's recall@3 on the dev set
# is already over 0.9 for in-corpus queries, and beyond that we just
# spend tokens on lower-confidence noise.
MAX_HITS = 3

# Snapshot key on ``state.metadata`` where the augmenter caches its last
# call.  See :meth:`_cache_run_result`.
_STATE_RAG_KEY = "rag"


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
        return self._augment(
            state,
            max_solution_chars=PLANNER_SOLUTION_CHARS,
            max_description_chars=PLANNER_DESCRIPTION_CHARS,
            max_files=PLANNER_FILES,
        )

    def for_solver(self, state: GlobalState) -> list[dict[str, Any]]:
        """Render hits with the solver-side per-field budget.

        Solver evidence has fewer competing fields than the planner JSON,
        so we let each ``solution_sketch`` claim more characters — the
        solver actually needs the algorithm details rather than a
        category-only summary.
        """
        return self._augment(
            state,
            max_solution_chars=SOLVER_SOLUTION_CHARS,
            max_description_chars=SOLVER_DESCRIPTION_CHARS,
            max_files=SOLVER_FILES,
        )

    def top_score(self, state: GlobalState) -> float:
        """Return the cosine of the top-1 hit, ``0.0`` when no hit exists.

        Used by the dispatch policy to relax solver-streak suppression
        when RAG strongly identifies a similar past challenge — a 4-streak
        of buggy scripts is much less likely to be a wrong-direction
        signal when the planner is being shown the *exact* writeup at
        score ≥ 0.6.

        Reads from the :data:`_STATE_RAG_KEY` cache when available; falls
        back to a fresh retrieval otherwise.  We deliberately do NOT
        invalidate the cache mid-run: the retrieval depends only on the
        immutable ``state.metadata["challenge"]``, so once we have it
        the score is good for the whole run.
        """
        if not self.enabled:
            return 0.0
        cached = self._cached_top_score(state)
        if cached is not None:
            return cached
        # Force one retrieval; this also populates the cache.
        self._augment(
            state,
            max_solution_chars=PLANNER_SOLUTION_CHARS,
            max_description_chars=PLANNER_DESCRIPTION_CHARS,
            max_files=PLANNER_FILES,
        )
        return self._cached_top_score(state) or 0.0

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _augment(
        self,
        state: GlobalState,
        *,
        max_solution_chars: int,
        max_description_chars: int,
        max_files: int,
    ) -> list[dict[str, Any]]:
        if not self.enabled:
            return []
        category = self._infer_category(state)
        query = self._build_query(state, category)
        if not query:
            return []
        excluded_ids, excluded_events = self._exclusion_keys(state)

        try:
            assert self.retriever is not None  # narrowed by self.enabled
            hits: list[RetrievalHit] = self.retriever.retrieve(
                query,
                category=category,
                top_k=self.top_k,
                exclude_challenge_ids=excluded_ids,
                exclude_event_keys=excluded_events,
                require_solution_sketch=True,
            )
        except Exception:
            # Retrieval failure is never fatal: degrade to "no augmentation".
            return []

        rendered = [
            hit.to_prompt_dict(
                max_solution_chars=max_solution_chars,
                max_description_chars=max_description_chars,
                max_files=max_files,
            )
            for hit in hits
        ]
        self._cache_run_result(state, hits)
        return rendered

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
        wherever the calling prompt builder put it (planner snapshot or
        solver evidence).  We cache only what other components need
        without re-running retrieval.
        """
        cache: dict[str, Any] = {
            "top_score": float(hits[0].score) if hits else 0.0,
            "top_challenge_id": hits[0].challenge_id if hits else None,
            "hit_count": len(hits),
        }
        state.metadata[_STATE_RAG_KEY] = cache

    @staticmethod
    def _cached_top_score(state: GlobalState) -> float | None:
        cache = state.metadata.get(_STATE_RAG_KEY)
        if not isinstance(cache, dict):
            return None
        value = cache.get("top_score")
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
