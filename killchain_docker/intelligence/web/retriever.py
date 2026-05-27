"""Web retrieval orchestration: budget enforcement, caching, and source dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from killchain_docker.intelligence.hit import KnowledgeHit
from killchain_docker.intelligence.memdir.paths import web_cache_dir
from killchain_docker.intelligence.web.cache import WebCache
from killchain_docker.intelligence.web.client import WebFetchError, fetch_json
from killchain_docker.intelligence.web.policy import (
    MAX_CALLS_PER_RUN,
    MAX_RESULTS_PER_QUERY,
    PER_SOURCE_CALLS,
    redact_query,
)
from killchain_docker.intelligence.web.sources import exploitdb, mitre_attack, nvd
from killchain_docker.logging_utils import get_logger


LOGGER = get_logger(__name__)
_DEFAULT_SOURCES: tuple = (nvd, mitre_attack, exploitdb)


@dataclass
class WebBudget:
    """Mutable per-run budget tracker for outbound calls."""

    total_remaining: int = MAX_CALLS_PER_RUN
    per_source_remaining: dict[str, int] = field(default_factory=dict)

    def can_call(self, source: str) -> bool:
        if self.total_remaining <= 0:
            return False
        return self.per_source_remaining.get(source, PER_SOURCE_CALLS) > 0

    def consume(self, source: str) -> None:
        self.total_remaining = max(0, self.total_remaining - 1)
        remaining = self.per_source_remaining.get(source, PER_SOURCE_CALLS)
        self.per_source_remaining[source] = max(0, remaining - 1)


class WebRetriever:
    """Coordinator that runs the registered sources within budget."""

    def __init__(
        self,
        *,
        memory_root: Path,
        sources: tuple[Any, ...] = _DEFAULT_SOURCES,
        fetch: Callable[..., dict[str, Any]] = fetch_json,
        budget: WebBudget | None = None,
    ) -> None:
        self.cache = WebCache(web_cache_dir(memory_root))
        self.sources = tuple(sources)
        self.fetch = fetch
        self.budget = budget or WebBudget()

    def search(
        self,
        *,
        query: str,
        category: str,
        keywords: tuple[str, ...] = (),
        blocked_tokens: tuple[str, ...] = (),
        per_source_limit: int = MAX_RESULTS_PER_QUERY,
    ) -> list[KnowledgeHit]:
        redacted = redact_query(query, blocked_tokens=blocked_tokens)
        if not redacted.query:
            return []
        merged: list[KnowledgeHit] = []
        for source in self.sources:
            name = getattr(source, "SOURCE_NAME", source.__name__)
            cached = self.cache.get(source=name, query=redacted.query)
            if cached is not None:
                merged.extend(_hit_from_payload(name, cached.payload))
                continue
            if not self.budget.can_call(name):
                continue
            try:
                hits = source.search(
                    query=redacted.query,
                    category=category,
                    keywords=keywords,
                    fetch_json=self.fetch,
                    limit=per_source_limit,
                )
            except WebFetchError as exc:
                LOGGER.info(
                    "web source unreachable",
                    extra={"source": name, "reason": str(exc)},
                )
                continue
            except Exception:
                LOGGER.exception(
                    "web source crashed", extra={"source": name}
                )
                continue
            self.budget.consume(name)
            payload = [_hit_to_payload(hit) for hit in hits]
            self.cache.put(source=name, query=redacted.query, payload=payload)
            merged.extend(hits)
        return merged


def _hit_to_payload(hit: KnowledgeHit) -> dict[str, Any]:
    return {
        "source": hit.source,
        "scope": hit.scope,
        "key": hit.key,
        "title": hit.title,
        "summary": hit.summary,
        "value": hit.value,
        "score": hit.score,
        "extra": dict(hit.extra or {}),
    }


def _hit_from_payload(source_name: str, payload: list[dict[str, Any]]) -> list[KnowledgeHit]:
    out: list[KnowledgeHit] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        out.append(
            KnowledgeHit(
                source=str(entry.get("source") or f"web/{source_name}"),
                scope=str(entry.get("scope") or ""),
                key=str(entry.get("key") or ""),
                title=str(entry.get("title") or ""),
                summary=str(entry.get("summary") or ""),
                value=str(entry.get("value") or ""),
                score=float(entry.get("score") or 0.0),
                extra=dict(entry.get("extra") or {}),
            )
        )
    return out
