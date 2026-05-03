"""Tiny local ONNX embedding model used for dense retrieval.

We deliberately wrap :class:`fastembed.TextEmbedding` rather than calling it
directly so the rest of the package can:

1. Treat ``fastembed`` as an *optional* dependency — when it isn't installed
   the retriever degrades to "no augmentation" instead of crashing.
2. Hot-swap the embedding backend in tests via :class:`StubEmbedder`, so unit
   tests don't need a 67 MB ONNX download.
3. Cache encoded corpus matrices to disk keyed by ``(model, content-hash)``,
   so re-running on the same corpus is instant and we never burn a few
   seconds on the same encode round-trip every cycle.

The default model is ``BAAI/bge-small-en-v1.5`` — 384-dim, ~67 MB on disk,
512 input-token context, English-only.  Override via the
``AUTOPENTEST_RAG_EMBED_MODEL`` env var if you need ``all-MiniLM-L6-v2``
(slightly smaller but lower quality on retrieval benchmarks) or
``BAAI/bge-small-zh-v1.5`` (for Chinese-language CTFs).
"""

from __future__ import annotations

import hashlib
import os
import threading
from pathlib import Path
from typing import Iterable, Protocol, runtime_checkable

import numpy as np

DEFAULT_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"


@runtime_checkable
class EmbeddingBackend(Protocol):
    """Protocol the retriever consumes — only :meth:`encode` is required."""

    @property
    def dimension(self) -> int: ...

    @property
    def model_id(self) -> str: ...

    def encode(self, texts: list[str]) -> np.ndarray: ...


class FastEmbedBackend:
    """Wrap a :class:`fastembed.TextEmbedding` and L2-normalize its output.

    The fastembed model is loaded lazily on first :meth:`encode` so importing
    this module is cheap (no ONNX session up front, no network calls until
    we actually have something to embed).  Subsequent calls reuse the same
    session under a thread lock — fastembed's session is not safe to share
    across threads on macOS arm64 in our experience.
    """

    def __init__(
        self,
        model_id: str = DEFAULT_EMBEDDING_MODEL,
        *,
        cache_dir: str | Path | None = None,
    ) -> None:
        self._model_id = model_id
        self._cache_dir = str(Path(cache_dir)) if cache_dir is not None else None
        self._model = None
        self._lock = threading.Lock()
        self._dim: int | None = None

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def dimension(self) -> int:
        if self._dim is None:
            # Force a 1-token encode to discover the dim.  The result is
            # itself cached for the rest of the process lifetime.
            self.encode(["."])
        assert self._dim is not None
        return self._dim

    def _ensure_model(self):
        if self._model is not None:
            return self._model
        try:
            from fastembed import TextEmbedding
        except ImportError as exc:
            raise EmbeddingUnavailable(
                "fastembed is not installed; `pip install fastembed numpy` "
                "or set AUTOPENTEST_RAG_DISABLED=1 to disable knowledge "
                "augmentation entirely."
            ) from exc
        kwargs: dict[str, object] = {"model_name": self._model_id}
        if self._cache_dir:
            kwargs["cache_dir"] = self._cache_dir
        self._model = TextEmbedding(**kwargs)
        return self._model

    def encode(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dimension if self._dim else 1), dtype=np.float32)
        with self._lock:
            model = self._ensure_model()
            vectors = list(model.embed(list(texts)))
        if not vectors:
            return np.zeros((0, self._dim or 1), dtype=np.float32)
        matrix = np.asarray(vectors, dtype=np.float32)
        # L2-normalize so cosine similarity collapses to a plain dot product
        # at retrieval time.  We do it here once for the corpus and once per
        # query, instead of every cycle inside the retriever inner loop.
        norms = np.linalg.norm(matrix, axis=1, keepdims=True)
        # Avoid divide-by-zero on degenerate empty texts.
        norms[norms == 0.0] = 1.0
        matrix = matrix / norms
        if self._dim is None:
            self._dim = matrix.shape[1]
        return matrix


class StubEmbedder:
    """Deterministic embedder for unit tests — no ONNX, no network.

    Hashes each input text into a fixed-dim vector via SHA-256 expansion so
    semantically identical inputs map to identical vectors and unrelated
    inputs are nearly orthogonal.  Quality is irrelevant — we only need
    reproducibility and zero install footprint.
    """

    def __init__(self, dim: int = 32, model_id: str = "stub:sha256") -> None:
        self._dim = dim
        self._model_id = model_id

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def model_id(self) -> str:
        return self._model_id

    def encode(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self._dim), dtype=np.float32)
        out = np.zeros((len(texts), self._dim), dtype=np.float32)
        for i, text in enumerate(texts):
            digest = hashlib.sha256(text.encode("utf-8")).digest()
            # Expand the 32-byte digest to ``dim`` floats by repeating + offsetting.
            buf = (digest * ((self._dim // len(digest)) + 1))[: self._dim]
            arr = np.frombuffer(buf, dtype=np.uint8).astype(np.float32)
            arr = (arr - 127.5) / 127.5
            out[i] = arr
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        norms[norms == 0.0] = 1.0
        return out / norms


class EmbeddingUnavailable(RuntimeError):
    """Raised when fastembed isn't installed (caught by :func:`get_retriever`)."""


class CachedEmbeddingMatrix:
    """Persist an encoded corpus matrix to disk keyed by its content hash.

    The corpus rarely changes (only when we re-download the NYUCTF dataset),
    so we want subsequent process startups to skip re-encoding ~57 documents.
    The cache key combines the embedder's ``model_id`` (so swapping models
    invalidates the file automatically) with a SHA-256 over the joined
    embedding texts.
    """

    def __init__(
        self,
        backend: EmbeddingBackend,
        cache_dir: str | Path | None = None,
    ) -> None:
        self._backend = backend
        if cache_dir is None:
            xdg = os.getenv("XDG_CACHE_HOME") or str(Path.home() / ".cache")
            cache_dir = Path(xdg) / "autopentest_rag" / "matrices"
        self._cache_dir = Path(cache_dir)

    def encode_corpus(self, texts: Iterable[str]) -> np.ndarray:
        text_list = list(texts)
        cache_path = self._resolve_cache_path(text_list)
        if cache_path.is_file():
            try:
                cached = np.load(cache_path)
                if cached.shape[0] == len(text_list):
                    return cached.astype(np.float32, copy=False)
            except (OSError, ValueError):
                # Corrupt cache — fall through to re-encode and overwrite.
                pass
        matrix = self._backend.encode(text_list)
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = cache_path.with_suffix(cache_path.suffix + ".tmp")
            # ``numpy.save`` appends ``.npy`` when given a *path*, so we hand
            # it a binary file handle instead — that way the on-disk name is
            # exactly ``cache_path`` and the atomic ``replace`` works.
            with open(tmp_path, "wb") as fh:
                np.save(fh, matrix, allow_pickle=False)
            tmp_path.replace(cache_path)
        except OSError:
            # Cache failure is non-fatal — we already have the matrix in RAM.
            pass
        return matrix

    def _resolve_cache_path(self, texts: list[str]) -> Path:
        hasher = hashlib.sha256()
        hasher.update(self._backend.model_id.encode("utf-8"))
        hasher.update(b"\x00")
        for text in texts:
            hasher.update(text.encode("utf-8"))
            hasher.update(b"\x00")
        digest = hasher.hexdigest()[:16]
        safe_model = self._backend.model_id.replace("/", "_").replace(":", "_")
        return self._cache_dir / f"{safe_model}_{digest}.npy"


def build_default_embedder() -> FastEmbedBackend:
    """Construct the default fastembed backend honoring env-var overrides."""
    model_id = (os.getenv("AUTOPENTEST_RAG_EMBED_MODEL") or "").strip() or DEFAULT_EMBEDDING_MODEL
    cache_dir = (os.getenv("AUTOPENTEST_RAG_EMBED_CACHE_DIR") or "").strip() or None
    return FastEmbedBackend(model_id=model_id, cache_dir=cache_dir)
