"""Build the per-challenge knowledge corpus from a NYUCTF dataset directory.

Each challenge folder under ``<dataset_root>/<split>/<year>/<event>/<category>/<chall>/``
contributes one :class:`KnowledgeEntry` carrying the canonical id, the
``challenge.json`` metadata, and the README writeup (with the ``## Solution``
block isolated as a compact ``solution_sketch``).

The shape is intentionally minimal so a downstream embedder can encode each
entry into a single dense vector without us having to pick which paragraphs
"matter".  The retriever then uses dense cosine similarity (no BM25) for
ranking — see :mod:`killchain_docker.knowledge.embedder` and
:mod:`killchain_docker.knowledge.retriever`.
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
_SOLUTION_FILE_RE = re.compile(
    r"(?i)(?:^|[-_.])(solve|solver|solution|writeup|exploit|decrypt)(?:[-_.]|$)"
)
_TEXT_SOLUTION_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".java",
    ".js",
    ".md",
    ".php",
    ".pl",
    ".py",
    ".rb",
    ".sage",
    ".sh",
    ".txt",
}
_SUPPORTING_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".php",
    ".pl",
    ".py",
    ".rb",
}
_MAX_COMPANION_FILES = 3
_MAX_COMPANION_CHARS = 9000
_LEADING_BLOCK_COMMENT_RE = re.compile(r"\A\s*/\*.*?\*/\s*", re.DOTALL)
_LEADING_HASH_COMMENT_RE = re.compile(r"\A(?:\s*#[^\n]*\n){3,}\s*")


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
        description = _merged_description(
            str(meta.get("description") or "").strip(),
            _readme_description(readme) if readme else "",
        )

        solution_sketch = extract_solution_sketch(readme)
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
                solution_sketch=augment_solution_sketch(
                    chall_dir,
                    solution_sketch,
                    challenge_files=files,
                ),
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


def _merged_description(metadata_description: str, readme_description: str) -> str:
    metadata_text = metadata_description.strip()
    readme_text = readme_description.strip()
    if not metadata_text:
        return readme_text
    if not readme_text:
        return metadata_text

    metadata_l = metadata_text.lower()
    readme_l = readme_text.lower()
    if metadata_l in readme_l:
        return readme_text
    if readme_l in metadata_l:
        return metadata_text
    return f"{metadata_text}\n\n{readme_text}"


def augment_solution_sketch(
    challenge_dir: Path,
    solution_sketch: str,
    *,
    challenge_files: list[str] | None = None,
) -> str:
    """Append small companion solver files to a README solution sketch.

    Some NYUCTF writeups use ``## Solution`` only as a pointer to files such
    as ``solve.py`` or ``foo-solve.py``.  Including those text files keeps RAG
    method hints faithful without adding challenge-specific branches.
    """

    sections = [solution_sketch.strip()] if solution_sketch.strip() else []
    for path in _knowledge_companion_files(challenge_dir, challenge_files or []):
        text = _safe_read_text(path).strip()
        if not text:
            continue
        rel = path.relative_to(challenge_dir).as_posix()
        suffix = path.suffix.lstrip(".") or "text"
        excerpt = _compact_companion_text(text, suffix)[:_MAX_COMPANION_CHARS]
        sections.append(
            f"Companion solution file: {rel}\n"
            f"```{suffix}\n{excerpt}\n```"
        )
    return "\n\n".join(sections).strip()


def _knowledge_companion_files(challenge_dir: Path, challenge_files: list[str]) -> list[Path]:
    if not challenge_dir.is_dir():
        return []
    solution_files = [
        path
        for path in challenge_dir.iterdir()
        if _is_solution_companion(path)
    ]
    selected = sorted(solution_files, key=lambda path: path.name.lower())[:_MAX_COMPANION_FILES]
    if len(selected) >= _MAX_COMPANION_FILES:
        return selected

    excluded_names = {Path(item).name for item in challenge_files}
    selected_set = {path.name for path in selected}
    supporting = [
        path
        for path in challenge_dir.iterdir()
        if _is_supporting_source(path, excluded_names, selected_set)
    ]
    slots = _MAX_COMPANION_FILES - len(selected)
    return [*selected, *sorted(supporting, key=lambda path: path.name.lower())[:slots]]


def _is_solution_companion(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name.lower() in {"readme.md", "challenge.json"}:
        return False
    if path.suffix.lower() not in _TEXT_SOLUTION_SUFFIXES:
        return False
    return bool(_SOLUTION_FILE_RE.search(path.stem))


def _compact_companion_text(text: str, suffix: str) -> str:
    """Drop leading license banners so prompt budget keeps executable logic."""

    cleaned = text.strip()
    if suffix in {"c", "cc", "cpp", "h", "hpp", "java", "js", "php"}:
        cleaned = _LEADING_BLOCK_COMMENT_RE.sub("", cleaned, count=1).lstrip()
    if suffix in {"py", "sh", "rb", "pl"}:
        cleaned = _LEADING_HASH_COMMENT_RE.sub("", cleaned, count=1).lstrip()
    return cleaned


def _is_supporting_source(
    path: Path,
    excluded_names: set[str],
    selected_names: set[str],
) -> bool:
    if not path.is_file() or path.name in selected_names:
        return False
    if path.name in excluded_names or path.name.lower() in {"readme.md", "challenge.json"}:
        return False
    return path.suffix.lower() in _SUPPORTING_SOURCE_SUFFIXES
