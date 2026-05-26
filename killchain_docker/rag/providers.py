"""Provider interface for replaceable RAG backends."""

from __future__ import annotations

from typing import Iterable, Protocol

from killchain_docker.rag.hit import RetrievalHit


class RagProvider(Protocol):
    """Minimal provider interface consumed by the runtime augmenter."""

    def __len__(self) -> int: ...

    def hit_by_challenge_id(
        self,
        challenge_id: str,
        *,
        score: float = 1.0,
        require_solution_sketch: bool = True,
    ) -> RetrievalHit | None: ...

    def retrieve(
        self,
        query: str,
        *,
        category: str | None = None,
        top_k: int = 3,
        exclude_challenge_ids: Iterable[str] = (),
        exclude_event_keys: Iterable[tuple[str, str] | str] = (),
        require_solution_sketch: bool = True,
    ) -> list[RetrievalHit]: ...

