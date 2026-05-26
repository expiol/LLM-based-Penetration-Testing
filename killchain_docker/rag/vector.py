"""Dense-vector RAG provider for answer-excluded retrieval experiments."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import numpy as np

from killchain_docker.knowledge.corpus import KnowledgeEntry
from killchain_docker.knowledge.embedder import CachedEmbeddingMatrix, EmbeddingBackend
from killchain_docker.rag.hit import RetrievalHit, event_key, retrieval_hit_from_entry


class VectorKnowledgeProvider:
    """Dense cosine provider over a fixed corpus of ``KnowledgeEntry``."""

    def __init__(
        self,
        entries: list[KnowledgeEntry],
        embedder: EmbeddingBackend,
        *,
        cache_dir: str | Path | None = None,
    ) -> None:
        self.entries = list(entries)
        self.embedder = embedder
        self._by_challenge_id = {
            entry.challenge_id: entry for entry in self.entries if entry.challenge_id
        }
        self._by_category: dict[str, list[int]] = {}
        for i, entry in enumerate(self.entries):
            self._by_category.setdefault(entry.category, []).append(i)
        if not self.entries:
            self._matrix = np.zeros((0, embedder.dimension or 1), dtype=np.float32)
        else:
            cached = CachedEmbeddingMatrix(embedder, cache_dir=cache_dir)
            texts = [entry.embedding_text for entry in self.entries]
            self._matrix = cached.encode_corpus(texts)

    def __len__(self) -> int:
        return len(self.entries)

    def hit_by_challenge_id(
        self,
        challenge_id: str,
        *,
        score: float = 1.0,
        require_solution_sketch: bool = True,
    ) -> RetrievalHit | None:
        key = str(challenge_id or "").strip()
        if not key:
            return None
        entry = self._by_challenge_id.get(key)
        if entry is None:
            return None
        if require_solution_sketch and not entry.solution_sketch:
            return None
        return retrieval_hit_from_entry(entry, score)

    def retrieve(
        self,
        query: str,
        *,
        category: str | None = None,
        top_k: int = 3,
        exclude_challenge_ids: Iterable[str] = (),
        exclude_event_keys: Iterable[tuple[str, str] | str] = (),
        require_solution_sketch: bool = True,
    ) -> list[RetrievalHit]:
        if top_k <= 0 or len(self.entries) == 0:
            return []
        cleaned_query = (query or "").strip()
        if not cleaned_query:
            return []

        cat_key = (category or "").strip().lower()
        if cat_key and cat_key in self._by_category:
            candidate_indices = list(self._by_category[cat_key])
        else:
            candidate_indices = list(range(len(self.entries)))
        if not candidate_indices:
            return []

        query_matrix = self.embedder.encode([cleaned_query])
        if query_matrix.size == 0:
            return []
        query_vec = query_matrix[0]
        sub_matrix = self._matrix[candidate_indices]
        scores = sub_matrix @ query_vec
        order = np.argsort(-scores)

        excluded_ids = {str(c).strip() for c in exclude_challenge_ids if c}
        excluded_events = {_coerce_event_key(item) for item in exclude_event_keys}
        excluded_events.discard("")

        hits: list[RetrievalHit] = []
        for rank in order:
            idx = candidate_indices[int(rank)]
            entry = self.entries[idx]
            if entry.challenge_id in excluded_ids:
                continue
            if event_key(entry.year, entry.event) in excluded_events:
                continue
            if require_solution_sketch and not entry.solution_sketch:
                continue
            hits.append(retrieval_hit_from_entry(entry, float(scores[int(rank)])))
            if len(hits) >= top_k:
                break
        return hits


def _coerce_event_key(value: tuple[str, str] | list[str] | str) -> str:
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return event_key(value[0], value[1])
    return str(value or "").strip().lower()

