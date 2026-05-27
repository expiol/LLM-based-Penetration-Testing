"""Build a manifest of durable memory records for relevant-recall."""

from __future__ import annotations

from dataclasses import dataclass

from killchain_docker.memory.durable import DurableMemoryRecord


_HEAD_CHARS = 200
_TITLE_CHARS = 80


@dataclass(frozen=True)
class MemoryManifestEntry:
    """One row passed to the recall selector."""

    slug: str
    scope: str
    key: str
    title: str
    head: str

    def to_dict(self) -> dict[str, str]:
        return {
            "slug": self.slug,
            "scope": self.scope,
            "key": self.key,
            "title": self.title,
            "head": self.head,
        }


def build_manifest(
    records: list[DurableMemoryRecord],
) -> list[MemoryManifestEntry]:
    """Convert durable records into a compact recall manifest.

    The manifest deliberately omits full ``value`` bodies — the selector picks
    based on title plus the first ``_HEAD_CHARS`` characters, mirroring the
    file-header selection used by claude-code's ``findRelevantMemories``.
    """

    out: list[MemoryManifestEntry] = []
    for record in records:
        title = (record.title or record.key)[:_TITLE_CHARS]
        head = (record.value or "").strip().splitlines()
        head_text = " ".join(line.strip() for line in head if line.strip())[:_HEAD_CHARS]
        out.append(
            MemoryManifestEntry(
                slug=record.slug,
                scope=record.scope.value,
                key=record.key,
                title=title,
                head=head_text,
            )
        )
    return out
