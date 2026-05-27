"""On-disk JSONL cache for web retrieval results."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


CACHE_TTL_S = 7 * 24 * 60 * 60  # 7 days


@dataclass(frozen=True)
class CachedResponse:
    fetched_at: float
    payload: list[dict[str, Any]]


def _digest(query: str) -> str:
    return hashlib.sha1(query.encode("utf-8")).hexdigest()[:24]


class WebCache:
    """Simple JSONL cache keyed by source + redacted query digest."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _path(self, source: str) -> Path:
        return self.root / f"web_{source}.jsonl"

    def get(self, *, source: str, query: str) -> CachedResponse | None:
        path = self._path(source)
        if not path.exists():
            return None
        digest = _digest(query)
        try:
            with path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if record.get("digest") != digest:
                        continue
                    fetched_at = float(record.get("fetched_at") or 0.0)
                    if time.time() - fetched_at > CACHE_TTL_S:
                        return None
                    payload = record.get("payload") or []
                    if not isinstance(payload, list):
                        return None
                    return CachedResponse(fetched_at=fetched_at, payload=payload)
        except OSError:
            return None
        return None

    def put(self, *, source: str, query: str, payload: list[dict[str, Any]]) -> None:
        path = self._path(source)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "digest": _digest(query),
            "query": query[:500],
            "fetched_at": time.time(),
            "payload": payload,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=True))
            fh.write("\n")
