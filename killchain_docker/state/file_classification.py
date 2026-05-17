"""Single source of truth for filename-to-kind classification.

Used by planner, dispatch policy, tool execution, and worker context
normalization so all layers agree on what counts as
"source", "binary", "archive", "pcap", "sqlite", or "repo".
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

from killchain_docker._compat import StrEnum


class FileKind(StrEnum):
    SOURCE = "source"
    BINARY = "binary"
    ARCHIVE = "archive"
    PCAP = "pcap"
    SQLITE = "sqlite"
    REPO = "repo"
    UNKNOWN = "unknown"


SOURCE_EXTS: frozenset[str] = frozenset({
    ".py", ".js", ".rb", ".pl", ".sh", ".c", ".cpp", ".h", ".java",
    ".php", ".go", ".rs", ".sage", ".txt", ".md", ".yml", ".yaml",
    ".json", ".xml", ".html", ".css", ".sql", ".lua", ".r",
})

ARCHIVE_EXTS: frozenset[str] = frozenset({
    ".zip", ".tar", ".gz", ".tgz", ".bz2", ".7z", ".rar", ".xz",
})

PCAP_EXTS: frozenset[str] = frozenset({".pcap", ".pcapng", ".cap"})

SQLITE_EXTS: frozenset[str] = frozenset({".db", ".sqlite", ".sqlite3"})

# Canonical extension-to-kind map.  Order of evaluation: archive > pcap > sqlite > source.
EXT_TO_KIND: dict[str, FileKind] = {
    **{ext: FileKind.ARCHIVE for ext in ARCHIVE_EXTS},
    **{ext: FileKind.PCAP for ext in PCAP_EXTS},
    **{ext: FileKind.SQLITE for ext in SQLITE_EXTS},
    **{ext: FileKind.SOURCE for ext in SOURCE_EXTS},
}


def _ext(filename: str) -> str:
    name = filename.strip()
    if not name:
        return ""
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1].lower()


def classify(filename: str) -> FileKind:
    """Return the most specific FileKind for *filename*.

    Files without a recognized extension fall through to BINARY.
    Repo paths must be flagged separately by the caller (no extension hint).
    """
    ext = _ext(filename)
    if not ext:
        return FileKind.BINARY
    return EXT_TO_KIND.get(ext, FileKind.BINARY)


def files_by_kind(filenames: Iterable[str]) -> dict[FileKind, list[str]]:
    """Group an iterable of filenames into a {kind: [files]} dict."""
    grouped: dict[FileKind, list[str]] = {kind: [] for kind in FileKind}
    for name in filenames or ():
        kind = classify(name)
        if name not in grouped[kind]:
            grouped[kind].append(name)
    return grouped


def filter_by_kind(filenames: Iterable[str], kind: FileKind) -> list[str]:
    """Return the subset of *filenames* whose classify() matches *kind*."""
    return [name for name in filenames or () if classify(name) == kind]


def looks_like_source(filename: str) -> bool:
    return classify(filename) == FileKind.SOURCE


def looks_like_archive(filename: str) -> bool:
    return classify(filename) == FileKind.ARCHIVE


def looks_like_pcap(filename: str) -> bool:
    return classify(filename) == FileKind.PCAP


def looks_like_sqlite(filename: str) -> bool:
    return classify(filename) == FileKind.SQLITE


def split_source_and_binary(filenames: Iterable[str]) -> tuple[list[str], list[str]]:
    """Convenience helper used by planner: (source_files, non_source_files)."""
    sources: list[str] = []
    others: list[str] = []
    for name in filenames or ():
        if classify(name) == FileKind.SOURCE:
            sources.append(name)
        else:
            others.append(name)
    return sources, others


def basename(path: str) -> str:
    """Filesystem-agnostic basename for archive members like ``arch.tgz:dir/file.py``."""
    if ":" in path:
        path = path.split(":", 1)[1]
    return Path(path).name
