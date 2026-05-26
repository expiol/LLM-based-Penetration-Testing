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
* No challenge-id exclusion by default.  Assisted runs may surface a
  challenge-identical method hint so the benchmark can isolate execution
  ability from retrieval quality.  Pass non-empty ``exclude_challenge_ids``
  for answer-excluded retrieval checks.
* Category is a soft pre-filter: when the current challenge category matches
  at least one corpus entry, restrict ranking to that subset.  Otherwise
  search the full corpus so an unusual category label still surfaces
  useful hits.
* :func:`get_retriever` is fail-soft: if the dataset isn't downloaded,
  ``fastembed`` isn't installed, or ``AUTOPENTEST_RAG_DISABLED=1`` is set,
  it returns ``None`` and the caller skips augmentation. Invalid RAG policy
  names fail fast so strict/oracle experiments cannot be silently mixed.
"""

from __future__ import annotations

import os
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import numpy as np

from killchain_docker.logging_utils import get_logger
from killchain_docker.knowledge.corpus import KnowledgeEntry, load_corpus
from killchain_docker.knowledge.embedder import (
    CachedEmbeddingMatrix,
    EmbeddingBackend,
    EmbeddingUnavailable,
    build_default_embedder,
)
from killchain_docker.state.constants import validatable_flag_candidate


LOGGER = get_logger(__name__)
RAG_MODE_ENV = "AUTOPENTEST_RAG_MODE"
RAG_MODE_ORACLE = "oracle"
RAG_MODE_STRICT = "strict"
RAG_MODE_DISABLED = "disabled"
RAG_MODES = frozenset({RAG_MODE_ORACLE, RAG_MODE_STRICT, RAG_MODE_DISABLED})
_FLAG_LITERAL_RE = re.compile(r"\b[A-Za-z0-9_]{2,32}\{[^{}\n]{1,160}\}")
_BARE_FLAG_LITERAL_RE = re.compile(r"\b[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}\b")
_BARE_FLAG_CONTEXT_RE = re.compile(
    r"(?:flag|answer|secret|submit|final(?:\s+plaintext)?|plaintext)\s*"
    r"(?:is|:|=|->|-)?\s*$",
    re.IGNORECASE,
)
_FILE_ANSWER_WORDS = frozenset({"answer", "secret", "password", "passphrase"})


def event_key(year: str, event: str) -> str:
    """Stable key for comparing corpus events across runtime metadata."""

    year_text = str(year or "").strip()
    event_text = str(event or "").strip()
    if not year_text or not event_text:
        return ""
    normalized_event = re.sub(r"\s+", "-", event_text.lower())
    return f"{year_text}:{normalized_event}"


def redact_flag_literals(text: str, *, file_path: bool = False) -> str:
    """Remove literal flag values from retrieved writeups.

    RAG should transfer methods and evidence expectations, not memorize or
    leak concrete benchmark answers.
    """

    redacted = _FLAG_LITERAL_RE.sub("[REDACTED_FLAG]", text)

    def replace_bare(match: re.Match[str]) -> str:
        token = match.group(0)
        if token == "REDACTED_FLAG":
            return token
        if not any(separator in token for separator in "_.-"):
            return token
        candidate = token
        suffix = ""
        if file_path:
            stem, dot, ext = token.rpartition(".")
            if dot and stem and ext and _bare_file_literal_context(stem):
                candidate = stem
                suffix = f".{ext}"
        if not validatable_flag_candidate(candidate):
            stem, dot, ext = token.rpartition(".")
            if not dot or not validatable_flag_candidate(stem):
                return token
            candidate = stem
            suffix = f".{ext}"
        if not _bare_flag_literal_context(text, match.start(), candidate):
            if not file_path or not _bare_file_literal_context(candidate):
                return token
        return f"[REDACTED_FLAG]{suffix}"

    return _BARE_FLAG_LITERAL_RE.sub(replace_bare, redacted)


def _bare_file_literal_context(token: str) -> bool:
    if _high_uppercase_ratio(token):
        return True
    parts = {part for part in re.split(r"[_.-]+", token.lower()) if part}
    return bool(parts & _FILE_ANSWER_WORDS)


def _high_uppercase_ratio(token: str) -> bool:
    letters = [ch for ch in token if ch.isalpha()]
    if not letters:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    return uppercase / len(letters) >= 0.6


def _bare_flag_literal_context(text: str, token_start: int, token: str) -> bool:
    prefix = text[max(0, token_start - 80) : token_start]
    if _high_uppercase_ratio(token):
        return True
    return bool(_BARE_FLAG_CONTEXT_RE.search(prefix))


def redact_file_path_literals(path: str) -> str:
    """Redact answer-like file names while preserving useful extensions."""

    return redact_flag_literals(path, file_path=True)


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

    @property
    def event_key(self) -> str:
        return event_key(self.year, self.event)

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
            "description": redact_flag_literals(self.description)[
                :max_description_chars
            ],
            "files": [
                redact_file_path_literals(path) for path in self.files[:max_files]
            ],
            "solution_sketch": redact_flag_literals(self.solution_sketch)[
                :max_solution_chars
            ],
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
        """Return a direct corpus hit for *challenge_id* when available."""

        key = str(challenge_id or "").strip()
        if not key:
            return None
        entry = self._by_challenge_id.get(key)
        if entry is None:
            return None
        if require_solution_sketch and not entry.solution_sketch:
            return None
        return _entry_to_hit(entry, score)

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
        """Return up to *top_k* highest-scored entries matching the query.

        ``category`` is treated as a soft pre-filter when set: if at least
        one corpus entry uses that category, only those entries are ranked;
        otherwise the full corpus is ranked. This keeps unusual
        category labels (e.g. ``stego``, ``ppc``) from silently producing
        empty results.

        ``exclude_challenge_ids`` and ``exclude_event_keys`` (stable event
        key strings or ``(year, event)`` tuples) are applied AFTER ranking, so
        callers can still get hits when the only category match would have
        been the current challenge itself.

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
            hits.append(_entry_to_hit(entry, float(scores[int(rank)])))
            if len(hits) >= top_k:
                break
        return hits


def _entry_to_hit(entry: KnowledgeEntry, score: float) -> RetrievalHit:
    return RetrievalHit(
        challenge_id=entry.challenge_id,
        name=entry.name,
        category=entry.category,
        year=entry.year,
        event=entry.event,
        description=entry.description,
        solution_sketch=entry.solution_sketch,
        files=list(entry.files),
        score=float(score),
    )


def _coerce_event_key(value: tuple[str, str] | list[str] | str) -> str:
    if isinstance(value, (tuple, list)) and len(value) >= 2:
        return event_key(value[0], value[1])
    return str(value or "").strip().lower()


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


def rag_mode(override: str | None = None) -> str:
    """Return the active RAG policy mode.

    ``oracle`` is the first-round execution benchmark mode: the full
    configured corpus is available as supplemental technical context.
    ``strict`` excludes same challenge and same event hits for decontaminated
    runs. ``disabled`` turns augmentation off entirely.
    """

    raw = (
        (override if override is not None else os.getenv(RAG_MODE_ENV) or "")
        .strip()
        .lower()
    )
    if raw in RAG_MODES:
        return raw
    if raw:
        choices = ", ".join(sorted(RAG_MODES))
        raise ValueError(f"unknown RAG mode {raw!r}; expected one of: {choices}")
    if _env_flag("AUTOPENTEST_RAG_DISABLED"):
        return RAG_MODE_DISABLED
    if _env_flag("AUTOPENTEST_RAG_STRICT_EXCLUDE"):
        return RAG_MODE_STRICT
    return RAG_MODE_ORACLE


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

    Callers that need answer-excluded retrieval can either select strict mode
    or pass ``exclude_event_keys`` explicitly.
    """
    return rag_mode() == RAG_MODE_STRICT


def oracle_context_status(
    challenge_id: str,
    *,
    dataset_root: str | None = None,
) -> dict[str, object]:
    """Return whether oracle mode has actionable same-challenge context.

    This reads the corpus metadata directly instead of initializing the
    embedding backend. It is used as a cheap execution-benchmark preflight:
    oracle runs should only measure execution quality when a concrete
    solution sketch is actually available.
    """

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

    paths = _resolve_dataset_paths(dataset_root)
    if paths is None:
        return payload

    root, index_path = paths
    try:
        entries = load_corpus(root, index_path)
    except Exception:
        LOGGER.exception(
            "RAG oracle preflight failed", extra={"dataset_root": str(root)}
        )
        payload["status"] = "error"
        return payload

    payload["enabled"] = True
    for entry in entries:
        if entry.challenge_id != key:
            continue
        if entry.solution_sketch.strip():
            payload["status"] = "hit"
            payload["hint_count"] = 1
            return payload
        payload["status"] = "metadata_only"
        return payload

    payload["status"] = "miss"
    return payload


def actionable_oracle_challenge_ids(*, dataset_root: str | None = None) -> set[str]:
    """Return challenge ids with a non-empty oracle solution sketch."""

    paths = _resolve_dataset_paths(dataset_root)
    if paths is None:
        return set()

    root, index_path = paths
    try:
        entries = load_corpus(root, index_path)
    except Exception:
        LOGGER.exception(
            "RAG oracle corpus scan failed", extra={"dataset_root": str(root)}
        )
        return set()
    return {
        entry.challenge_id
        for entry in entries
        if entry.challenge_id and entry.solution_sketch.strip()
    }


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
    mode: str | None = None,
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

    resolved_mode = rag_mode(mode)
    if resolved_mode == RAG_MODE_DISABLED:
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
        LOGGER.warning("RAG disabled because dataset paths are unavailable")
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
                LOGGER.warning(
                    "RAG disabled because corpus is empty",
                    extra={"dataset_root": str(root)},
                )
                return None
            embedder = build_default_embedder()
            _ = embedder.dimension
            _RETRIEVER = KnowledgeRetriever(entries, embedder)
            _RETRIEVER_KEY = key
            LOGGER.info(
                "RAG retriever initialized",
                extra={
                    "dataset_root": str(root),
                    "entries": len(entries),
                    "rag_mode": resolved_mode,
                },
            )
            return _RETRIEVER
        except EmbeddingUnavailable:
            # Embedding library missing — permanent until pip install.
            _LOAD_FAILED_PERMANENTLY = True
            LOGGER.warning(
                "RAG disabled because embedding backend is unavailable",
                exc_info=True,
                extra={
                    "dataset_root": str(root),
                    "rag_mode": resolved_mode,
                    "model_id": model_id,
                },
            )
            return None
        except Exception:
            # ONNX init, model download race, transient corrupted cache, …
            # Latch with a timestamp so we don't hammer on every cycle, but
            # allow recovery without a restart.
            _LOAD_FAILED_AT = time.monotonic()
            LOGGER.exception(
                "RAG retriever initialization failed",
                extra={"dataset_root": str(root), "rag_mode": resolved_mode},
            )
            return None
