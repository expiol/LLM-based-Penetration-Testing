"""Default RAG provider factory and process-level caches."""

from __future__ import annotations

import os
import threading
import time

from killchain_docker.knowledge.corpus import load_corpus
from killchain_docker.knowledge.embedder import EmbeddingUnavailable, build_default_embedder
from killchain_docker.logging_utils import get_logger
from killchain_docker.rag.config import RAG_MODE_DISABLED, RAG_MODE_ORACLE, rag_mode
from killchain_docker.rag.oracle import DirectOracleProvider, load_oracle_provider, resolve_oracle_dataset_paths
from killchain_docker.rag.providers import RagProvider
from killchain_docker.rag.vector import VectorKnowledgeProvider


LOGGER = get_logger(__name__)
_LOCK = threading.Lock()
_ORACLE_PROVIDER: DirectOracleProvider | None = None
_ORACLE_KEY: str | None = None
_VECTOR_PROVIDER: VectorKnowledgeProvider | None = None
_VECTOR_KEY: tuple[str, str, str] | None = None
_LOAD_FAILED_PERMANENTLY: bool = False
_LOAD_FAILED_AT: float | None = None
_LOAD_RETRY_AFTER_S: float = 60.0


def reset_rag_provider_cache() -> None:
    """Forget cached providers and failure latches."""

    global _ORACLE_PROVIDER, _ORACLE_KEY, _VECTOR_PROVIDER, _VECTOR_KEY
    global _LOAD_FAILED_PERMANENTLY, _LOAD_FAILED_AT
    with _LOCK:
        _ORACLE_PROVIDER = None
        _ORACLE_KEY = None
        _VECTOR_PROVIDER = None
        _VECTOR_KEY = None
        _LOAD_FAILED_PERMANENTLY = False
        _LOAD_FAILED_AT = None


def build_default_provider(
    *,
    dataset_root: str | None = None,
    mode: str | None = None,
) -> RagProvider | None:
    """Return the default provider for the selected RAG mode.

    ``oracle`` uses direct corpus reads. ``strict`` uses the vector provider so
    answer-excluded ablation can still rank related challenges.
    """

    resolved_mode = rag_mode(mode)
    if resolved_mode == RAG_MODE_DISABLED:
        return None
    if resolved_mode == RAG_MODE_ORACLE:
        return _oracle_provider(dataset_root=dataset_root)
    return _vector_provider(dataset_root=dataset_root, mode=resolved_mode)


def _oracle_provider(*, dataset_root: str | None) -> DirectOracleProvider | None:
    global _ORACLE_PROVIDER, _ORACLE_KEY
    paths = resolve_oracle_dataset_paths(dataset_root)
    if paths is None:
        LOGGER.warning("RAG oracle disabled because dataset paths are unavailable")
        return None
    root, _idx = paths
    key = str(root)
    with _LOCK:
        if _ORACLE_PROVIDER is not None and _ORACLE_KEY == key:
            return _ORACLE_PROVIDER
        provider = load_oracle_provider(dataset_root=dataset_root)
        if provider is None:
            return None
        _ORACLE_PROVIDER = provider
        _ORACLE_KEY = key
        LOGGER.info(
            "RAG oracle provider initialized",
            extra={"dataset_root": str(root), "entries": len(provider)},
        )
        return provider


def _vector_provider(
    *,
    dataset_root: str | None,
    mode: str,
) -> VectorKnowledgeProvider | None:
    global _VECTOR_PROVIDER, _VECTOR_KEY, _LOAD_FAILED_PERMANENTLY, _LOAD_FAILED_AT
    if _LOAD_FAILED_PERMANENTLY:
        return None
    if _LOAD_FAILED_AT is not None:
        if (time.monotonic() - _LOAD_FAILED_AT) < _LOAD_RETRY_AFTER_S:
            return None
        _LOAD_FAILED_AT = None

    paths = resolve_oracle_dataset_paths(dataset_root)
    if paths is None:
        _LOAD_FAILED_PERMANENTLY = True
        LOGGER.warning("RAG vector provider disabled because dataset paths are unavailable")
        return None
    root, idx = paths
    model_id = (os.getenv("AUTOPENTEST_RAG_EMBED_MODEL") or "").strip()
    key = (str(root), str(idx), model_id)

    with _LOCK:
        if _VECTOR_PROVIDER is not None and _VECTOR_KEY == key:
            return _VECTOR_PROVIDER
        try:
            entries = load_corpus(root, idx)
            if not entries:
                _LOAD_FAILED_PERMANENTLY = True
                LOGGER.warning(
                    "RAG vector provider disabled because corpus is empty",
                    extra={"dataset_root": str(root)},
                )
                return None
            embedder = build_default_embedder()
            _ = embedder.dimension
            _VECTOR_PROVIDER = VectorKnowledgeProvider(entries, embedder)
            _VECTOR_KEY = key
            LOGGER.info(
                "RAG vector provider initialized",
                extra={
                    "dataset_root": str(root),
                    "entries": len(entries),
                    "rag_mode": mode,
                },
            )
            return _VECTOR_PROVIDER
        except EmbeddingUnavailable:
            _LOAD_FAILED_PERMANENTLY = True
            LOGGER.warning(
                "RAG vector provider disabled because embedding backend is unavailable",
                exc_info=True,
                extra={
                    "dataset_root": str(root),
                    "rag_mode": mode,
                    "model_id": model_id,
                },
            )
            return None
        except Exception:
            _LOAD_FAILED_AT = time.monotonic()
            LOGGER.exception(
                "RAG vector provider initialization failed",
                extra={"dataset_root": str(root), "rag_mode": mode},
            )
            return None

