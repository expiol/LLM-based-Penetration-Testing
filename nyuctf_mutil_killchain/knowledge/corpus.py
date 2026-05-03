"""Build the per-challenge knowledge corpus from a NYUCTF dataset directory.

Each challenge folder under ``<dataset_root>/<split>/<year>/<event>/<category>/<chall>/``
contributes one :class:`KnowledgeEntry` carrying the canonical id, the
``challenge.json`` metadata, and the README writeup (with the ``## Solution``
block isolated as a compact ``solution_sketch``).

The shape is intentionally minimal so a downstream embedder can encode each
entry into a single dense vector without us having to pick which paragraphs
"matter".  The retriever then uses dense cosine similarity (no BM25) for
ranking — see :mod:`nyuctf_mutil_killchain.knowledge.embedder` and
:mod:`nyuctf_mutil_killchain.knowledge.retriever`.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

# ``## Solution`` (case-insensitive) anywhere in the README, until the next
# ``##`` heading.  We deliberately stop at the next heading so unrelated
# sections (``## Setup``, ``## Build``) don't leak into the sketch.
_SOLUTION_HEADING_RE = re.compile(r"^\s*##+\s*solution\b.*$", re.IGNORECASE | re.MULTILINE)
_NEXT_HEADING_RE = re.compile(r"^\s*##+\s+", re.MULTILINE)


@dataclass(frozen=True)
class KnowledgeEntry:
    """One indexed challenge from the NYUCTF dataset."""

    challenge_id: str
    year: str
    event: str
    category: str
    name: str
    description: str
    files: list[str]
    writeup: str
    solution_sketch: str

    @property
    def embedding_text(self) -> str:
        """Bag-of-text the embedding model encodes into a single vector.

        Repeats the title and category (each twice) so they get extra weight
        in the encoder's bag-of-tokens behaviour, then mixes in description,
        file names, and the ``## Solution`` body.  We deliberately omit the
        full README — including a 3 KB writeup full of generic "the flag is
        hidden" prose dilutes the dense vector toward the corpus mean and
        actually hurts top-k recall.
        """
        parts: list[str] = [
            f"name: {self.name} ({self.name})",
            f"category: {self.category} ({self.category})",
        ]
        if self.description:
            parts.append(f"description: {self.description}")
        if self.files:
            parts.append("files: " + ", ".join(self.files))
        if self.solution_sketch:
            parts.append("solution: " + self.solution_sketch)
        return "\n".join(parts)


def extract_solution_sketch(readme: str) -> str:
    """Pull the ``## Solution`` body out of a NYUCTF README.

    Returns an empty string when the heading is missing.  Stops at the next
    ``##`` heading so we don't accidentally grab unrelated sections such as
    ``## Setup`` or ``## Build``.
    """
    match = _SOLUTION_HEADING_RE.search(readme)
    if match is None:
        return ""
    tail = readme[match.end():]
    next_heading = _NEXT_HEADING_RE.search(tail)
    body = tail[: next_heading.start()] if next_heading else tail
    return body.strip()


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _safe_read_json(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def load_corpus(
    dataset_root: Path | str,
    split_index_json: Path | str,
) -> list[KnowledgeEntry]:
    """Load every challenge listed in *split_index_json* into a KnowledgeEntry.

    *dataset_root* is the directory that contains the split-named subfolder
    (e.g. ``~/.nyuctf/v20250206``); *split_index_json* is the per-split
    manifest emitted by ``nyuctf.download`` (e.g. ``development_dataset.json``).

    Entries with neither ``challenge.json`` nor ``README.md`` are skipped
    silently — those are usually placeholder folders that survived the
    upstream cleanup pass.
    """
    dataset_root = Path(dataset_root)
    split_index_json = Path(split_index_json)
    index = _safe_read_json(split_index_json) or {}
    entries: list[KnowledgeEntry] = []

    for challenge_id, info in index.items():
        rel_path = str(info.get("path", "")).strip()
        if not rel_path:
            continue
        chall_dir = dataset_root / rel_path
        if not chall_dir.is_dir():
            continue

        meta = _safe_read_json(chall_dir / "challenge.json") or {}
        readme = _safe_read_text(chall_dir / "README.md")
        category = (info.get("category") or meta.get("category") or "misc").lower()
        files = list(meta.get("files") or [])
        description = str(meta.get("description") or "").strip()
        if not description and readme:
            # README often duplicates the challenge.json description under
            # ``## Description`` — fall back to that so query-time semantic
            # matching still has a phrase to align against.
            description = _readme_description(readme)

        entries.append(
            KnowledgeEntry(
                challenge_id=str(challenge_id),
                year=str(info.get("year") or ""),
                event=str(info.get("event") or ""),
                category=category,
                name=str(meta.get("name") or info.get("challenge") or challenge_id),
                description=description,
                files=files,
                writeup=readme,
                solution_sketch=extract_solution_sketch(readme),
            )
        )

    return entries


_DESCRIPTION_HEADING_RE = re.compile(
    r"^\s*##+\s*description\b.*$", re.IGNORECASE | re.MULTILINE
)


def _readme_description(readme: str) -> str:
    match = _DESCRIPTION_HEADING_RE.search(readme)
    if match is None:
        return ""
    tail = readme[match.end():]
    next_heading = _NEXT_HEADING_RE.search(tail)
    body = tail[: next_heading.start()] if next_heading else tail
    return body.strip()
