"""Temporary direct-oracle RAG provider.

This provider reads challenge writeups directly from the configured NYUCTF
development corpus.  It is intentionally small and replaceable: future
security-knowledge retrieval should satisfy ``RagProvider`` without touching
planner or worker code.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable

from killchain_docker.knowledge.corpus import KnowledgeEntry, load_corpus
from killchain_docker.logging_utils import get_logger
from killchain_docker.rag.config import RAG_MODE_ORACLE
from killchain_docker.rag.hit import RetrievalHit, event_key, retrieval_hit_from_entry


LOGGER = get_logger(__name__)


class DirectOracleProvider:
    """Read oracle corpus entries directly without an embedding backend."""

    def __init__(self, entries: list[KnowledgeEntry]) -> None:
        self.entries = list(entries)
        self._by_challenge_id = {
            entry.challenge_id: entry for entry in self.entries if entry.challenge_id
        }
        self._by_category: dict[str, list[KnowledgeEntry]] = {}
        for entry in self.entries:
            self._by_category.setdefault(entry.category, []).append(entry)

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
        """Return deterministic lexical fallback hits from the oracle corpus."""

        if top_k <= 0:
            return []
        cleaned_query = (query or "").strip()
        if not cleaned_query:
            return []
        cat_key = (category or "").strip().lower()
        entries = (
            list(self._by_category[cat_key])
            if cat_key and cat_key in self._by_category
            else list(self.entries)
        )
        excluded_ids = {str(item).strip() for item in exclude_challenge_ids if item}
        excluded_events = {_coerce_event_key(item) for item in exclude_event_keys}
        excluded_events.discard("")
        query_terms = _terms(cleaned_query)

        ranked: list[tuple[float, KnowledgeEntry]] = []
        for entry in entries:
            if entry.challenge_id in excluded_ids:
                continue
            if event_key(entry.year, entry.event) in excluded_events:
                continue
            if require_solution_sketch and not entry.solution_sketch:
                continue
            score = _lexical_score(query_terms, entry)
            if score <= 0:
                continue
            ranked.append((score, entry))

        ranked.sort(key=lambda item: (-item[0], item[1].challenge_id))
        return [
            retrieval_hit_from_entry(entry, min(1.0, score))
            for score, entry in ranked[:top_k]
        ]


def load_oracle_provider(*, dataset_root: str | None = None) -> DirectOracleProvider | None:
    paths = resolve_oracle_dataset_paths(dataset_root)
    if paths is None:
        return None
    root, index_path = paths
    try:
        entries = load_corpus(root, index_path)
    except Exception:
        LOGGER.exception(
            "RAG oracle corpus load failed", extra={"dataset_root": str(root)}
        )
        return None
    if not entries:
        LOGGER.warning(
            "RAG oracle corpus is empty", extra={"dataset_root": str(root)}
        )
        return None
    return DirectOracleProvider(entries)


def oracle_context_status(
    challenge_id: str,
    *,
    dataset_root: str | None = None,
) -> dict[str, object]:
    """Return whether oracle mode has actionable same-challenge context."""

    key = str(challenge_id or "").strip()
    payload: dict[str, object] = {
        "mode": RAG_MODE_ORACLE,
        "enabled": False,
        "status": "unavailable",
        "policy": "supplemental_context",
        "hint_count": 0,
    }
    if not key:
        payload["status"] = "empty_query"
        return payload

    provider = load_oracle_provider(dataset_root=dataset_root)
    if provider is None:
        return payload

    payload["enabled"] = True
    hit = provider.hit_by_challenge_id(key, require_solution_sketch=False)
    if hit is None:
        payload["status"] = "miss"
        return payload
    if hit.solution_sketch.strip():
        payload["status"] = "hit"
        payload["hint_count"] = 1
        return payload
    payload["status"] = "metadata_only"
    return payload


def actionable_oracle_challenge_ids(*, dataset_root: str | None = None) -> set[str]:
    """Return challenge ids with a non-empty oracle solution sketch."""

    provider = load_oracle_provider(dataset_root=dataset_root)
    if provider is None:
        return set()
    return {
        entry.challenge_id
        for entry in provider.entries
        if entry.challenge_id and entry.solution_sketch.strip()
    }


def resolve_oracle_dataset_paths(
    override: str | None = None,
) -> tuple[Path, Path] | None:
    """Return ``(dataset_root, split_index_json)`` or ``None`` when missing."""

    if override:
        root = Path(override).expanduser().resolve()
    else:
        env_root = (os.getenv("AUTOPENTEST_RAG_DATASET_ROOT") or "").strip()
        if env_root:
            root = Path(env_root).expanduser().resolve()
        else:
            try:
                from nyuctf.dataset import CTFDataset
            except Exception:
                LOGGER.debug(
                    "RAG dataset auto-discovery unavailable",
                    exc_info=True,
                    extra={"dataset_root_env": bool(env_root)},
                )
                return None
            try:
                ds = CTFDataset(split="development")
            except Exception:
                LOGGER.debug(
                    "RAG dataset auto-discovery failed",
                    exc_info=True,
                    extra={"split": "development"},
                )
                return None
            root = Path(ds.basedir)

    if not root.is_dir():
        return None
    candidate = root / "development_dataset.json"
    if not candidate.is_file():
        return None
    return root, candidate


def _coerce_event_key(value: tuple[str, str] | list[str] | str) -> str:
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return event_key(value[0], value[1])
    return str(value or "").strip().lower()


def _terms(text: str) -> set[str]:
    return {
        term.lower()
        for term in re.findall(r"[A-Za-z0-9_]{3,}", text)
        if term.lower() not in {"name", "category", "description", "files", "the"}
    }


def _lexical_score(query_terms: set[str], entry: KnowledgeEntry) -> float:
    if not query_terms:
        return 0.0
    entry_terms = _terms(entry.embedding_text)
    overlap = len(query_terms & entry_terms)
    if overlap == 0:
        return 0.0
    return overlap / max(1, len(query_terms))

