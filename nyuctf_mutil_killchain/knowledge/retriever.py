"""Knowledge retriever: dense cosine search over a NYUCTF challenge corpus.

Lazily builds an embedding matrix over the development split and serves it
via :func:`get_retriever`, a thread-safe module-level singleton.  The
retriever is the only entry point used by ``orchestrator.planning`` so the
planner doesn't have to thread the dataset path / model name / cache dir
through itself.

Key design choices:

* ``BAAI/bge-small-en-v1.5`` (384-dim, ~67 MB ONNX) as the default encoder.
  All vectors are L2-normalized inside the embedder, so cosine similarity
  collapses to a plain dot product here.
* No self-exclusion by default — the user explicitly chose the upper-bound
  setting where the retriever is allowed to surface the *current* challenge
  itself.  That makes the retriever effectively an "oracle hint provider"
  when running on the same split it indexes.  Pass non-empty
  ``exclude_challenge_ids`` to opt back into self-exclusion.
* Category is a soft pre-filter: when the current challenge category matches
  at least one corpus entry, restrict ranking to that subset.  Otherwise
  fall back to the full corpus so an unusual category label still surfaces
  useful hits.
* :func:`get_retriever` is fail-soft: if the dataset isn't downloaded,
  ``fastembed`` isn't installed, or ``AUTOPENTEST_RAG_DISABLED=1`` is set,
  it returns ``None`` and the caller skips augmentation.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

from nyuctf_mutil_killchain.knowledge.corpus import KnowledgeEntry, load_corpus
from nyuctf_mutil_killchain.knowledge.embedder import (
    CachedEmbeddingMatrix,
    EmbeddingBackend,
    EmbeddingUnavailable,
    build_default_embedder,
)


@dataclass(frozen=True)
class RetrievalHit:
    """A single ranked KnowledgeEntry returned to a prompt builder."""

    challenge_id: str
    name: str
    category: str
    year: str
    event: str
    description: str
    solution_sketch: str
    files: list[str]
    score: float

    def to_prompt_dict(
        self,
        max_solution_chars: int = 1500,
        max_description_chars: int = 280,
        max_files: int = 8,
    ) -> dict[str, object]:
        """Render into the compact dict shape used in the planner prompt.

        Uses tight per-field budgets so injecting top-k hits stays under
        ~2 KB regardless of how chatty the original README was.
        """
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


class KnowledgeRetriever:
    """Dense cosine retriever over a fixed corpus of :class:`KnowledgeEntry`.

    The embedding matrix is built once at construction time and reused for
    every query — encoding 57 documents with ``bge-small-en-v1.5`` takes
    ~1.5s on Apple Silicon, and the on-disk cache (see :class:`CachedEmbeddingMatrix`)
    drops that to ~30 ms on subsequent runs.
    """

    def __init__(
        self,
        entries: list[KnowledgeEntry],
        embedder: EmbeddingBackend,
        *,
        cache_dir: str | Path | None = None,
    ) -> None:
        self.entries = list(entries)
        self.embedder = embedder
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

    def retrieve(
        self,
        query: str,
        *,
        category: str | None = None,
        top_k: int = 3,
        exclude_challenge_ids: Iterable[str] = (),
        exclude_event_keys: Iterable[tuple[str, str]] = (),
        require_solution_sketch: bool = True,
    ) -> list[RetrievalHit]:
        """Return up to *top_k* highest-scored entries matching the query.

        ``category`` is treated as a soft pre-filter when set: if at least
        one corpus entry uses that category, only those entries are ranked;
        otherwise we fall back to the full corpus.  This keeps unusual
        category labels (e.g. ``stego``, ``ppc``) from silently producing
        empty results.

        ``exclude_challenge_ids`` and ``exclude_event_keys`` (sets of
        ``(year, event)`` tuples) are applied AFTER ranking, so callers can
        still get hits when the only category match would have been the
        current challenge itself.

        ``require_solution_sketch`` filters out entries without a
        ``## Solution`` block — those are typically infrastructure or
        placeholder challenges with no actionable content for the planner.
        """
        if top_k <= 0 or len(self.entries) == 0:
            return []
        cleaned_query = (query or "").strip()
        if not cleaned_query:
            return []

        cat_key = (category or "").strip().lower()
        candidate_indices: list[int]
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

        # Vectors are L2-normalized inside the embedder, so the dot product
        # equals cosine similarity in [-1, 1].
        sub_matrix = self._matrix[candidate_indices]
        scores = sub_matrix @ query_vec  # shape (len(candidate_indices),)
        order = np.argsort(-scores)

        excluded_ids = {str(c).strip() for c in exclude_challenge_ids if c}
        excluded_events = {
            (str(year).strip(), str(event).strip())
            for year, event in exclude_event_keys
            if year or event
        }

        hits: list[RetrievalHit] = []
        for rank in order:
            idx = candidate_indices[int(rank)]
            entry = self.entries[idx]
            if entry.challenge_id in excluded_ids:
                continue
            if (entry.year, entry.event) in excluded_events:
                continue
            if require_solution_sketch and not entry.solution_sketch:
                continue
            hits.append(
                RetrievalHit(
                    challenge_id=entry.challenge_id,
                    name=entry.name,
                    category=entry.category,
                    year=entry.year,
                    event=entry.event,
                    description=entry.description,
                    solution_sketch=entry.solution_sketch,
                    files=list(entry.files),
                    score=float(scores[int(rank)]),
                )
            )
            if len(hits) >= top_k:
                break
        return hits


# ----------------------------------------------------------------------
# Module-level singleton + env-var configuration
# ----------------------------------------------------------------------

_LOCK = threading.Lock()
_RETRIEVER: KnowledgeRetriever | None = None
_RETRIEVER_KEY: tuple[str, str, str] | None = None
#: Permanent disable: dataset / corpus / embedding lib is structurally absent.
#: Never retried in-process because the cause cannot self-heal without a
#: code or environment change.
_LOAD_FAILED_PERMANENTLY: bool = False
#: Transient disable: ONNX init crash, model download race, etc.  Backoff
#: for ``_LOAD_RETRY_AFTER_S`` seconds then try again so a single hiccup
#: does not disable RAG for the rest of the process.
_LOAD_FAILED_AT: float | None = None
_LOAD_RETRY_AFTER_S: float = 60.0


def _env_flag(name: str) -> bool:
    return (os.getenv(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def default_top_k() -> int:
    raw = (os.getenv("AUTOPENTEST_RAG_TOP_K") or "").strip()
    if not raw:
        return 3
    try:
        value = int(raw)
    except ValueError:
        return 3
    return max(1, min(value, 8))


def strict_event_exclusion_enabled() -> bool:
    """Honor ``AUTOPENTEST_RAG_STRICT_EXCLUDE`` for callers that want it.

    Off by default per the user's "no self-exclusion" choice.  Callers that
    need the conservative behaviour can either flip the env var or pass
    ``exclude_event_keys`` explicitly.
    """
    return _env_flag("AUTOPENTEST_RAG_STRICT_EXCLUDE")


def _resolve_dataset_paths(
    override: str | None = None,
) -> tuple[Path, Path] | None:
    """Return ``(dataset_root, split_index_json)`` or ``None`` when missing.

    Resolution order:

    1. Explicit ``override`` argument.
    2. ``AUTOPENTEST_RAG_DATASET_ROOT`` env var.
    3. ``CTFDataset(split="development").basedir`` — i.e. wherever
       ``python -m nyuctf.download`` placed the dataset on this machine.

    The returned ``split_index_json`` is always
    ``<root>/development_dataset.json`` since we deliberately index the
    *development* split as the writeup corpus.
    """
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
                return None
            try:
                ds = CTFDataset(split="development")
            except Exception:
                return None
            root = Path(ds.basedir)

    if not root.is_dir():
        return None
    candidate = root / "development_dataset.json"
    if not candidate.is_file():
        return None
    return root, candidate


def reset_retriever_cache() -> None:
    """Forget the cached retriever and clear failure latches.

    Useful for tests and for callers that want to re-init RAG after fixing
    a missing dataset or model without restarting the process.
    """
    global _RETRIEVER, _RETRIEVER_KEY, _LOAD_FAILED_PERMANENTLY, _LOAD_FAILED_AT
    with _LOCK:
        _RETRIEVER = None
        _RETRIEVER_KEY = None
        _LOAD_FAILED_PERMANENTLY = False
        _LOAD_FAILED_AT = None


def get_retriever(
    *,
    dataset_root: str | None = None,
) -> KnowledgeRetriever | None:
    """Return the process-wide retriever, building it on first call.

    Returns ``None`` when RAG is disabled, the dataset is unavailable, the
    embedding backend is missing, or the corpus is empty.  Callers should
    treat ``None`` as "no augmentation available" and proceed normally.

    Failure modes are split:

    * **Permanent** (missing dataset / empty corpus / missing embedding lib)
      → ``_LOAD_FAILED_PERMANENTLY`` latches True for the rest of the
      process; the env needs a real change to recover.
    * **Transient** (ONNX init crash, model download race, etc.) → backoff
      for :data:`_LOAD_RETRY_AFTER_S` seconds via ``_LOAD_FAILED_AT``,
      then retry on the next call so a single hiccup does not disable
      RAG forever.
    """
    global _RETRIEVER, _RETRIEVER_KEY, _LOAD_FAILED_PERMANENTLY, _LOAD_FAILED_AT

    if _env_flag("AUTOPENTEST_RAG_DISABLED"):
        return None
    if _LOAD_FAILED_PERMANENTLY:
        return None
    if _LOAD_FAILED_AT is not None:
        if (time.monotonic() - _LOAD_FAILED_AT) < _LOAD_RETRY_AFTER_S:
            return None
        _LOAD_FAILED_AT = None  # cooldown elapsed; allow one retry

    paths = _resolve_dataset_paths(dataset_root)
    if paths is None:
        # Treat as permanent: dataset path resolution failed (no env var,
        # no nyuctf CTFDataset, or root not a directory).  A retry won't
        # help until the operator fixes the install.
        _LOAD_FAILED_PERMANENTLY = True
        return None
    root, idx = paths

    model_id = (os.getenv("AUTOPENTEST_RAG_EMBED_MODEL") or "").strip()
    key = (str(root), str(idx), model_id)

    with _LOCK:
        if _RETRIEVER is not None and _RETRIEVER_KEY == key:
            return _RETRIEVER
        try:
            entries = load_corpus(root, idx)
            if not entries:
                _LOAD_FAILED_PERMANENTLY = True
                return None
            embedder = build_default_embedder()
            _RETRIEVER = KnowledgeRetriever(entries, embedder)
            _RETRIEVER_KEY = key
            return _RETRIEVER
        except EmbeddingUnavailable:
            # Embedding library missing — permanent until pip install.
            _LOAD_FAILED_PERMANENTLY = True
            return None
        except Exception:
            # ONNX init, model download race, transient corrupted cache, …
            # Latch with a timestamp so we don't hammer on every cycle, but
            # allow recovery without a restart.
            _LOAD_FAILED_AT = time.monotonic()
            return None
