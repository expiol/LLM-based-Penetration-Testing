"""RAG over the NYU CTF development split.

Indexes per-challenge metadata + writeups (the README ``## Solution`` block)
into a dense embedding store so the planner and solver can retrieve top-k
similar past challenges and inject their solution sketches into prompts as
in-context hints.

Public surface:

* :class:`KnowledgeRetriever` — dense cosine retriever over the corpus.
* :class:`RetrievalHit` — one ranked entry returned to a caller.
* :func:`get_retriever` — module-level singleton honoring env-var config.
* :class:`KnowledgeAugmenter` — high-level facade that turns a
  :class:`GlobalState` into prompt-ready writeup hints; this is what
  planner / solver / dispatch consume.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.knowledge.augmenter import (
    MAX_HITS,
    KnowledgeAugmenter,
    RagContext,
    RagHit,
)
from nyuctf_mutil_killchain.knowledge.retriever import (
    KnowledgeRetriever,
    RetrievalHit,
    get_retriever,
    reset_retriever_cache,
)

__all__ = [
    "MAX_HITS",
    "KnowledgeAugmenter",
    "KnowledgeRetriever",
    "RagContext",
    "RagHit",
    "RetrievalHit",
    "get_retriever",
    "reset_retriever_cache",
]
