"""RAG hit model and audit-safe redaction helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass

from killchain_docker.knowledge.corpus import KnowledgeEntry
from killchain_docker.state.constants import validatable_flag_candidate


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
    """Remove literal flag values from retrieved writeups."""

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


def redact_file_path_literals(path: str) -> str:
    """Redact answer-like file names while preserving useful extensions."""

    return redact_flag_literals(path, file_path=True)


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


@dataclass(frozen=True)
class RetrievalHit:
    """A single ranked knowledge item returned to a prompt builder."""

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
        """Render into the compact dict shape used in the planner prompt."""

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


def retrieval_hit_from_entry(entry: KnowledgeEntry, score: float) -> RetrievalHit:
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

