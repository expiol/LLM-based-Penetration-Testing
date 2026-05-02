"""Flag-shape extraction and decoding heuristics for worker output."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from nyuctf_mutil_killchain.state.constants import (
    BRACKET_SPAN_PATTERN,
    COMMON_FLAG_PREFIXES,
    FLAG_PATTERN,
    FLAG_BODY_MAX_LEN,
    FLAG_BODY_MIN_LEN,
    plausible_flag,
)

_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_BLOB_PATTERN = re.compile(r"(?:0x)?([0-9a-fA-F]{20,})")


def _try_decode_blob(blob: str) -> list[str]:
    """Attempt common CTF encodings on a blob and return any flag-like results."""
    decoded: list[str] = []
    stripped = blob.strip()
    if not stripped or len(stripped) < 8:
        return decoded

    if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", stripped):
        for variant in (stripped, stripped + "=", stripped + "=="):
            try:
                raw = base64.b64decode(variant, validate=True)
                text = raw.decode("utf-8", errors="ignore")
                if FLAG_PATTERN.search(text):
                    decoded.extend(FLAG_PATTERN.findall(text))
            except Exception:
                pass

    if re.fullmatch(r"[0-9a-fA-F]{16,}", stripped) and len(stripped) % 2 == 0:
        try:
            raw = binascii.unhexlify(stripped)
            text = raw.decode("utf-8", errors="ignore")
            if FLAG_PATTERN.search(text):
                decoded.extend(FLAG_PATTERN.findall(text))
        except Exception:
            pass

    try:
        text = codecs.decode(stripped, "rot_13")
        if FLAG_PATTERN.search(text) and not FLAG_PATTERN.search(stripped):
            decoded.extend(FLAG_PATTERN.findall(text))
    except Exception:
        pass

    return decoded


# English/glue words that often immediately precede a ``{...}`` span in
# narrative output ("MY key for you is {body}").  We do NOT use these as
# candidate prefixes because they're never CTF flag prefixes — and burning
# top-N validation slots on them locks the real prefix out.  Match is
# case-insensitive against the lowered token.
_BRACKET_SPAN_NOISY_PREFIXES: frozenset[str] = frozenset({
    "is", "are", "was", "were", "be", "been", "being",
    "the", "a", "an", "this", "that", "these", "those",
    "in", "on", "at", "by", "to", "of", "for", "with", "as",
    "and", "or", "but", "so", "yet", "if", "else", "then",
    "you", "i", "we", "they", "he", "she", "it",
    "my", "your", "our", "their", "his", "her", "its",
    "got", "get", "found", "see", "saw", "have", "has", "had",
    "value", "result", "answer", "output", "input", "data",
})


_LOCAL_CONTEXT_WINDOW = 200


def _bracket_span_candidates(
    text: str,
    *,
    flag_format_prefix: str | None = None,
    max_spans: int = 3,
) -> list[str]:
    """Return ``prefix{body}`` candidates derived from free-floating ``{body}`` spans.

    This is the fallback that catches outputs like
    ``MY key for you is {And yes the nsa can read this to}`` where the
    canonical extractor finds nothing because the prefix is separated from
    ``{`` by punctuation/whitespace.  Prefix selection priority:

    1. Configured ``flag_format`` prefix (most authoritative).
    2. Any of :data:`COMMON_FLAG_PREFIXES` that appears within the local
       context (200 chars before the bracket).  csawpad's
       ``MY key for you is {body}`` has the literal word ``key`` right
       before the span — that's a strong signal.
    3. The remaining :data:`COMMON_FLAG_PREFIXES` entries as backup.
    4. The alnum word immediately preceding ``{`` (after filtering English
       glue words).  Covers exotic prefixes some challenges use.
    """
    if not text:
        return []
    out: list[str] = []
    seen_bodies: set[str] = set()
    for match in BRACKET_SPAN_PATTERN.finditer(text):
        body = match.group(1)
        if body in seen_bodies:
            continue
        seen_bodies.add(body)

        prefixes: list[str] = []
        # 1. Configured flag_format prefix wins.
        if flag_format_prefix:
            cleaned = flag_format_prefix.strip()
            if cleaned and cleaned.replace("_", "").isalnum():
                prefixes.append(cleaned)
        # 2. Common CTF prefixes that ALSO appear nearby (within
        #    _LOCAL_CONTEXT_WINDOW chars before the bracket) get top
        #    priority — narrative output often spells the prefix out.
        local = text[max(0, match.start() - _LOCAL_CONTEXT_WINDOW): match.start()]
        local_lower = local.lower()
        local_hits: list[str] = []
        for prefix in COMMON_FLAG_PREFIXES:
            if re.search(rf"\b{re.escape(prefix.lower())}\b", local_lower):
                if prefix not in local_hits:
                    local_hits.append(prefix)
        prefixes.extend(local_hits)
        # 3. Then the rest of the common prefixes as backup.
        for prefix in COMMON_FLAG_PREFIXES:
            if prefix not in prefixes:
                prefixes.append(prefix)
        # 4. Finally lift the alnum word immediately preceding the bracket
        #    as a fallback prefix, but reject obvious English glue words.
        word_match = re.search(r"([A-Za-z0-9_]{2,})\s*[^A-Za-z0-9_{}]*$", local)
        if word_match:
            word = word_match.group(1)
            if (
                word.lower() not in _BRACKET_SPAN_NOISY_PREFIXES
                and word not in prefixes
            ):
                prefixes.append(word)

        for prefix in prefixes:
            candidate = f"{prefix}{{{body}}}"
            if candidate in out:
                continue
            if not plausible_flag(candidate):
                continue
            out.append(candidate)
            if len(out) >= max_spans * len(COMMON_FLAG_PREFIXES):
                return out
    return out


def extract_flag_candidates(
    *values: str | None,
    flag_format_prefix: str | None = None,
) -> list[str]:
    """Extract unique flag-like tokens from the supplied strings.

    In addition to direct regex matches, attempts base64, hex, and ROT13
    decoding on long encoded-looking blobs.  Applies plausibility filtering
    to reject garbage matches that slip through the raw regex.

    When ``flag_format_prefix`` is provided and the canonical pattern misses
    but the input contains a free-floating ``{body}`` span, we also queue
    ``<flag_format_prefix>{body}`` for validation.  This catches the case
    where the LLM solver prints the answer as narrative prose
    (``MY key for you is {…}``) instead of a canonical ``flag{…}`` token.
    """

    candidates: list[str] = []

    def _add(item: str) -> None:
        if item in candidates:
            return
        if not plausible_flag(item):
            return
        candidates.append(item)

    for value in values:
        if not value:
            continue
        for match in FLAG_PATTERN.findall(value):
            _add(match)
        for blob in _BASE64_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                _add(decoded)
        for blob in _HEX_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                _add(decoded)

    # Bracket-span fallback: only fires when canonical extraction missed AND
    # the source text actually contains a printable bracket span.  This
    # deliberately runs last so canonical matches always win the dedupe
    # ordering.
    if not candidates:
        for value in values:
            for span in _bracket_span_candidates(
                value or "", flag_format_prefix=flag_format_prefix
            ):
                _add(span)

    return candidates


# Kept for backwards-compatible imports inside this package; the real
# plausibility logic now lives in :func:`state.constants.plausible_flag`.
_looks_like_plausible_flag = plausible_flag

__all__ = [
    "extract_flag_candidates",
    "_bracket_span_candidates",
    "_looks_like_plausible_flag",
    "FLAG_BODY_MAX_LEN",
    "FLAG_BODY_MIN_LEN",
]
