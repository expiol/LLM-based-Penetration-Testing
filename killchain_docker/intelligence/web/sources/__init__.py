"""Source registry for opt-in cybersecurity web retrieval."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Protocol

from killchain_docker.intelligence.hit import KnowledgeHit


class WebSource(Protocol):
    """A retrieval adapter against a single cybersecurity feed."""

    name: str

    def search(
        self,
        *,
        query: str,
        category: str,
        keywords: tuple[str, ...],
        fetch_json: Callable[..., dict[str, Any]],
        limit: int = 3,
    ) -> list[KnowledgeHit]:
        """Return up to ``limit`` knowledge hits for the given inputs."""


@dataclass
class WebQueryContext:
    """Bundle of inputs prepared by the augmenter for source modules."""

    query: str
    category: str
    keywords: tuple[str, ...] = ()
    redactions: tuple[str, ...] = field(default_factory=tuple)
