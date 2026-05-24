"""Flag-shape extraction and decoding heuristics for worker output."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from killchain_docker.logging_utils import get_logger
from killchain_docker.state.constants import (
    BRACKET_SPAN_PATTERN,
    CODE_STATEMENT_BODY_RE,
    FLAG_PATTERN,
    FLAG_PREFIX_MAX_LEN,
    PYTHON_REPR_BODY_RE,
    STRUCTURED_DIAGNOSTIC_BODY_RE,
    bare_token_shape,
    looks_like_escaped_byte_candidate,
    plausible_flag,
    validatable_flag_candidate,
)

LOGGER = get_logger(__name__)

_MAX_DECODE_BLOB_CHARS = 4096
_MAX_DECODE_BLOBS_PER_VALUE = 16
_BASE64_BLOB_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{{20,{_MAX_DECODE_BLOB_CHARS}}}={{0,2}}(?![A-Za-z0-9+/=])"
)
_HEX_BLOB_PATTERN = re.compile(
    rf"(?<![0-9a-fA-F])(?:0x)?([0-9a-fA-F]{{20,{_MAX_DECODE_BLOB_CHARS}}})(?![0-9a-fA-F])"
)
_BARE_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"([A-Za-z0-9][A-Za-z0-9_.-]{11,199})"
    r"(?![A-Za-z0-9_.-])"
)
_STRONG_BARE_CONTEXT_NEEDLES = (
    "flag",
    "secret",
    "answer",
)
_WEAK_BARE_CONTEXT_NEEDLES = (
    "candidate",
    "plaintext",
    "decrypted",
    "decoded",
)
_STRONG_BARE_CONTEXT_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(needle) for needle in _STRONG_BARE_CONTEXT_NEEDLES)
    + r")\b",
    re.IGNORECASE,
)
_WEAK_BARE_CONTEXT_RE = re.compile(
    r"\b(?:"
    + "|".join(re.escape(needle) for needle in _WEAK_BARE_CONTEXT_NEEDLES)
    + r")\b",
    re.IGNORECASE,
)
_KEY_BARE_CONTEXT_RE = re.compile(
    r"\bkey\b\s*(?::|=|\bis\b|\bvalue\b|\bfound\b|\brecovered\b)",
    re.IGNORECASE,
)
_KEY_MATERIAL_CONTEXT_RE = re.compile(
    r"\b(?:derived|trial|filler|xor|aes|rsa|des|vigenere|caesar|"
    r"encryption|decryption|cipher|keystream|stream|bytes?|repr|candidate)"
    r"\s+key\b"
    r"|\bkey\s+(?:bytes?|material|stream|candidate|schedule|first|ascii|"
    r"len(?:gth)?|size|index|offset)\b"
    r"|\bb['\"]",
    re.IGNORECASE,
)
_FLAG_OR_ANSWER_CONTEXT_RE = re.compile(r"\b(?:flag|answer)\b", re.IGNORECASE)
_NEGATIVE_BARE_CONTEXT_RE = re.compile(
    r"\b(?:no\s+flag|not\s+(?:a\s+)?flag|without\s+(?:a\s+)?flag|"
    r"flag\s+not\s+found|no\s+candidate|rejected\s+candidate|"
    r"candidate\b[^\r\n]{0,120}\bnot\s+found|not\s+found\s+in)\b",
    re.IGNORECASE,
)
_ASCII_ART_RUN_RE = re.compile(r"([A-Z])\1{2,}")
_ASCII_ART_MIN_RUNS = 8
_ASCII_ART_MIN_CANDIDATE_LEN = 12
_ASCII_ART_STEM_GAP = 32
_ASCII_ART_WORD_GAP = 22
_ASCII_ART_MULTI_STEM_LETTERS = frozenset("HMNUVWY")
_DATE_TIME_TOKEN_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T\s]\d{2}(?::\d{2}(?::\d{2})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$"
)
_RUNTIME_IDENTIFIER_TOKEN_RE = re.compile(
    r"^[A-Z][A-Z0-9_]*(?:"
    r"_ROOT|_DIR|_PATH|_HOME|_FILE|_FILES|_TMP|_TEMP|_CACHE|_CONFIG|_ENV|"
    r"_TOKEN|_SECRET|ROOT|DIR|PATH|HOME"
    r")$"
)
_LABELED_FLAG_LINE_RE = re.compile(
    r"(?im)^\s*(?:\[[^\]]+\]\s*)?"
    r"(?:"
    r"flag(?:\s+(?:found|candidate|recovered|plaintext|value))?"
    r"|recovered\s+flag"
    r"|final\s+flag"
    r"|answer"
    r"|secret"
    r")"
    r"\s*[:=]\s*(?P<value>[^\r\n]{4,240})"
)
_LABELED_NEGATIVE_RE = re.compile(
    r"\b(?:no\s+flag|not\s+found|none|n/a|manual\s+review|placeholder|"
    r"failed|mismatch|invalid)\b",
    re.IGNORECASE,
)


def _debug_decode_failure(operation: str, exc: Exception, *, value: str) -> None:
    LOGGER.debug(
        "flag candidate decode failed",
        exc_info=True,
        extra={"operation": operation, "value_length": len(value)},
    )


def _try_decode_blob(blob: str) -> list[str]:
    """Attempt common CTF encodings on a blob and return any flag-like results."""
    decoded: list[str] = []
    stripped = blob.strip()
    if not stripped or len(stripped) < 8:
        return decoded
    if len(stripped) > _MAX_DECODE_BLOB_CHARS:
        return decoded

    if _is_base64ish(stripped):
        for variant in _base64_decode_variants(stripped):
            try:
                raw = base64.b64decode(variant, validate=True)
                text = raw.decode("utf-8", errors="ignore")
                if FLAG_PATTERN.search(text):
                    decoded.extend(FLAG_PATTERN.findall(text))
            except Exception as exc:
                _debug_decode_failure("base64_blob", exc, value=stripped)

    if _is_hexish(stripped) and len(stripped) % 2 == 0:
        try:
            raw = binascii.unhexlify(stripped)
            text = raw.decode("utf-8", errors="ignore")
            if FLAG_PATTERN.search(text):
                decoded.extend(FLAG_PATTERN.findall(text))
        except Exception as exc:
            _debug_decode_failure("hex_blob", exc, value=stripped)

    try:
        text = codecs.decode(stripped, "rot_13")
        if FLAG_PATTERN.search(text) and not FLAG_PATTERN.search(stripped):
            decoded.extend(FLAG_PATTERN.findall(text))
    except Exception as exc:
        _debug_decode_failure("rot13_blob", exc, value=stripped)

    return decoded


def _base64_decode_variants(text: str) -> list[str]:
    stripped = str(text or "").strip()
    if not stripped:
        return []
    unpadded = stripped.rstrip("=")
    trailing_padding = len(stripped) - len(unpadded)
    if trailing_padding > 2 or "=" in unpadded:
        return []
    remainder = len(unpadded) % 4
    if remainder == 1:
        return []
    padding = (4 - remainder) % 4
    return [unpadded + ("=" * padding)]


def _is_base64ish(text: str) -> bool:
    return len(text) >= 16 and all(ch.isalnum() or ch in "+/=" for ch in text)


def _is_hexish(text: str) -> bool:
    return len(text) >= 16 and all(ch in "0123456789abcdefABCDEF" for ch in text)


def _line_context(text: str, start: int, end: int) -> str:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    return text[line_start:line_end]


def _looks_like_bare_flag_token(token: str, context: str) -> bool:
    if not bare_token_shape(token):
        return False
    if not validatable_flag_candidate(token):
        return False
    if _looks_like_runtime_identifier_token(token):
        return False
    if _is_hex_literal(token):
        return False
    if looks_like_escaped_byte_candidate(token):
        return False
    if _NEGATIVE_BARE_CONTEXT_RE.search(context):
        return False
    if (
        _KEY_MATERIAL_CONTEXT_RE.search(context)
        and not _FLAG_OR_ANSWER_CONTEXT_RE.search(context)
    ):
        return False

    high_signal = _looks_like_high_signal_bare_token(token)
    if _STRONG_BARE_CONTEXT_RE.search(context) or _KEY_BARE_CONTEXT_RE.search(context):
        return high_signal
    if _WEAK_BARE_CONTEXT_RE.search(context):
        return high_signal
    return False


def _looks_like_high_signal_bare_token(token: str) -> bool:
    if _DATE_TIME_TOKEN_RE.match(token):
        return False
    if _looks_like_runtime_identifier_token(token):
        return False
    if not any(sep in token for sep in "_-."):
        return False
    letters = [ch for ch in token if ch.isalpha()]
    if not letters:
        return False
    uppercase = sum(1 for ch in letters if ch.isupper())
    return uppercase / len(letters) >= 0.6


def _looks_like_runtime_identifier_token(token: str) -> bool:
    return bool(_RUNTIME_IDENTIFIER_TOKEN_RE.match(token or ""))


def _is_hex_literal(text: str) -> bool:
    body = text[2:] if text.lower().startswith("0x") else text
    return len(body) >= 16 and all(ch in "0123456789abcdefABCDEF" for ch in body)


def _bare_token_candidates(text: str) -> list[str]:
    out: list[str] = []
    for match in _BARE_TOKEN_RE.finditer(text or ""):
        token = match.group(1)
        context = _line_context(text, match.start(1), match.end(1))
        if not _looks_like_bare_flag_token(token, context):
            continue
        if token not in out:
            out.append(token)
    return out


def _labeled_flag_candidates(
    text: str,
    *,
    flag_format_prefix: str | None = None,
) -> list[str]:
    out: list[str] = []
    prefix = (flag_format_prefix or "flag").strip()
    prefix = prefix[:-1] if prefix.endswith("{") else prefix
    if not prefix or not all(ch.isalnum() or ch == "_" for ch in prefix):
        prefix = "flag"

    for match in _LABELED_FLAG_LINE_RE.finditer(text or ""):
        payload = _clean_labeled_payload(match.group("value"))
        if not payload:
            continue
        if validatable_flag_candidate(payload):
            if "{" not in payload and not _looks_like_high_signal_bare_token(payload):
                continue
            candidate = payload
        elif _looks_like_labeled_phrase(payload):
            candidate = f"{prefix}{{{payload}}}"
        else:
            continue
        if candidate not in out:
            out.append(candidate)
    return out


def _clean_labeled_payload(value: str) -> str:
    payload = re.sub(r"\s+", " ", str(value or "").strip())
    payload = payload.strip("`'\"")
    if payload.endswith((";", ",")):
        payload = payload[:-1].strip()
    return payload


def _looks_like_labeled_phrase(payload: str) -> bool:
    if not (4 <= len(payload) <= 200):
        return False
    if "{" in payload or "}" in payload:
        return False
    if _DATE_TIME_TOKEN_RE.match(payload):
        return False
    if not any(ch.isspace() for ch in payload):
        return False
    if not any(ch.isalnum() for ch in payload):
        return False
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in payload):
        return False
    if _LABELED_NEGATIVE_RE.search(payload):
        return False
    if STRUCTURED_DIAGNOSTIC_BODY_RE.search(payload):
        return False
    if PYTHON_REPR_BODY_RE.search(payload):
        return False
    if CODE_STATEMENT_BODY_RE.search(payload):
        return False
    return True


def _ascii_art_line_candidates(text: str) -> list[str]:
    out: list[str] = []
    for raw_line in (text or "").splitlines():
        for candidate in _ascii_art_line_candidate(raw_line):
            if candidate not in out:
                out.append(candidate)
    return out


def _ascii_art_line_candidate(line: str) -> list[str]:
    runs = list(_ASCII_ART_RUN_RE.finditer(line or ""))
    if len(runs) < _ASCII_ART_MIN_RUNS:
        return []

    letters: list[str] = []
    previous_end: int | None = None
    stem_open = False
    for run in runs:
        char = run.group(1)
        gap = 0 if previous_end is None else run.start() - previous_end
        if (
            letters
            and stem_open
            and char == letters[-1]
            and char in _ASCII_ART_MULTI_STEM_LETTERS
            and 0 < gap <= _ASCII_ART_STEM_GAP
        ):
            stem_open = False
            previous_end = run.end()
            continue

        if letters and gap >= _ASCII_ART_WORD_GAP and letters[-1] != "_":
            letters.append("_")
        letters.append(char)
        stem_open = char in _ASCII_ART_MULTI_STEM_LETTERS
        previous_end = run.end()

    candidate = re.sub(r"_+", "_", "".join(letters)).strip("_")
    if len(candidate) < _ASCII_ART_MIN_CANDIDATE_LEN:
        return []
    if "_" not in candidate:
        return []
    return _ascii_art_candidate_variants(candidate)


def _ascii_art_candidate_variants(candidate: str) -> list[str]:
    variants: list[str] = []
    collapsed = _collapse_spurious_single_letter_splits(candidate)
    for variant in (collapsed, candidate):
        if variant in variants:
            continue
        if validatable_flag_candidate(variant):
            variants.append(variant)
    return variants


def _collapse_spurious_single_letter_splits(candidate: str) -> str:
    tokens = [token for token in candidate.split("_") if token]
    collapsed: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        next_token = tokens[index + 1] if index + 1 < len(tokens) else ""
        if len(token) == 1 and token not in {"A", "I"} and len(next_token) >= 2:
            collapsed.append(token + next_token)
            index += 2
            continue
        collapsed.append(token)
        index += 1
    return "_".join(collapsed)


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

    This secondary extractor catches outputs where the canonical extractor
    finds no direct ``prefix{body}`` token because the prefix is separated from
    ``{`` by punctuation/whitespace.  Prefix selection priority:

    1. Configured ``flag_format`` prefix (most authoritative).
    2. Embedded ``{prefix: body}`` prefixes from the recovered text itself.
    3. The alnum word immediately preceding ``{`` after filtering English glue
       words.  No global prefix dictionary is synthesized.
    """
    if not text:
        return []
    out: list[str] = []
    seen_bodies: set[str] = set()
    for match in BRACKET_SPAN_PATTERN.finditer(text):
        if match.start() > 0 and (
            text[match.start() - 1].isalnum()
            or text[match.start() - 1] == "_"
        ):
            continue
        body = match.group(1)
        if body in seen_bodies:
            continue
        seen_bodies.add(body)

        # Handle "{prefix: actual_body}" pattern (e.g. "{key: VALUE}").
        # When the body starts with a known CTF prefix followed by ": " or ":",
        # split it into the embedded prefix and the real body.
        embedded_prefix_match = re.match(
            rf"([A-Za-z0-9_]{{2,{FLAG_PREFIX_MAX_LEN}}})\s*:\s*(.+)$",
            body,
            re.DOTALL,
        )
        if embedded_prefix_match:
            emb_prefix = embedded_prefix_match.group(1)
            emb_body = embedded_prefix_match.group(2).strip()
            if emb_body and len(emb_body) >= 4:
                # Emit the cleaned candidate directly: prefix{body}
                clean_candidate = f"{emb_prefix}{{{emb_body}}}"
                if clean_candidate not in out and plausible_flag(clean_candidate):
                    out.append(clean_candidate)
                    # The embedded prefix already gave us a high-quality
                    # candidate; skip the generic prefix-combination loop
                    # for this span to avoid emitting noisy variants like
                    # flag{key: VALUE}, CTF{key: VALUE}, etc.
                    continue

        prefixes: list[str] = []
        if flag_format_prefix:
            cleaned = flag_format_prefix.strip()
            if cleaned.endswith("{"):
                cleaned = cleaned[:-1]
            if cleaned and cleaned.replace("_", "").isalnum():
                prefixes.append(cleaned)
        local = text[max(0, match.start() - _LOCAL_CONTEXT_WINDOW): match.start()]
        words = re.findall(r"[A-Za-z0-9_]{2,}", local)
        for word in reversed(words):
            if (
                word.lower() not in _BRACKET_SPAN_NOISY_PREFIXES
                and word not in prefixes
            ):
                prefixes.append(word)
                break

        for prefix in prefixes:
            candidate = f"{prefix}{{{body}}}"
            if candidate in out:
                continue
            if not plausible_flag(candidate):
                continue
            out.append(candidate)
            if len(out) >= max_spans:
                return out
    return out


def extract_flag_candidates(
    *values: str | None,
    flag_format_prefix: str | None = None,
    include_bare: bool = True,
) -> list[str]:
    """Extract unique flag-like tokens from the supplied strings.

    In addition to direct regex matches, attempts base64, hex, and ROT13
    decoding on long encoded-looking blobs.  Applies plausibility filtering
    to reject garbage matches that slip through the raw regex.

    When ``include_bare`` is true, uppercase/separator-heavy bare tokens can
    be returned after stricter candidates miss. When ``flag_format_prefix`` is
    provided and the canonical pattern misses but the input contains a
    free-floating ``{body}`` span, we also queue ``<flag_format_prefix>{body}``
    for validation. This catches the case where a generated script prints the
    answer as narrative prose (``MY key for you is {…}``) instead of a
    canonical ``flag{…}`` token.
    """

    candidates: list[str] = []

    def _add(item: str) -> None:
        if item in candidates:
            return
        if "{" in item:
            if not plausible_flag(item):
                return
        elif not validatable_flag_candidate(item):
            return
        candidates.append(item)

    for value in values:
        if not value:
            continue
        for match in FLAG_PATTERN.findall(value):
            _add(match)
        for index, blob in enumerate(_BASE64_BLOB_PATTERN.findall(value)):
            if index >= _MAX_DECODE_BLOBS_PER_VALUE:
                break
            for decoded in _try_decode_blob(blob):
                _add(decoded)
        for index, blob in enumerate(_HEX_BLOB_PATTERN.findall(value)):
            if index >= _MAX_DECODE_BLOBS_PER_VALUE:
                break
            for decoded in _try_decode_blob(blob):
                _add(decoded)

    if include_bare and not candidates:
        for value in values:
            for token in _labeled_flag_candidates(
                value or "", flag_format_prefix=flag_format_prefix
            ):
                _add(token)
            for token in _ascii_art_line_candidates(value or ""):
                _add(token)
            for token in _bare_token_candidates(value or ""):
                _add(token)

    # Bracket-span extraction only fires when canonical extraction missed and
    # the source text actually contains a printable bracket span. This keeps
    # canonical matches first in the dedupe ordering.
    if not candidates:
        for value in values:
            for span in _bracket_span_candidates(
                value or "", flag_format_prefix=flag_format_prefix
            ):
                _add(span)

    return candidates


def encoding_cascade(near_miss: str) -> list[str]:
    """Try common encoding transformations on a near-miss flag candidate.

    When a near-miss is detected (correct prefix{body} shape but garbled bytes),
    this function attempts common fixes: strip non-printable, XOR 0xFF, reverse,
    base64/hex decode the body, rot13, strip null bytes.
    """
    if "{" not in near_miss or not near_miss.endswith("}"):
        return []
    prefix, _, body_brace = near_miss.partition("{")
    body = body_brace[:-1]
    if not body or not prefix:
        return []

    candidates: list[str] = []

    def _try(transformed_body: str) -> None:
        candidate = f"{prefix}{{{transformed_body}}}"
        if candidate not in candidates and candidate != near_miss and plausible_flag(candidate):
            candidates.append(candidate)

    # Strip non-printable characters
    printable_body = "".join(c for c in body if 32 <= ord(c) <= 126)
    if printable_body != body:
        _try(printable_body)

    # Strip null bytes
    no_null = body.replace("\x00", "")
    if no_null != body:
        _try(no_null)

    # XOR each byte with 0xFF
    try:
        xored = "".join(chr(ord(c) ^ 0xFF) for c in body)
        _try(xored)
    except (ValueError, OverflowError) as exc:
        _debug_decode_failure("xor_near_miss_body", exc, value=body)

    # Reverse byte order
    _try(body[::-1])

    # ROT13
    try:
        rot13_body = codecs.decode(body, "rot_13")
        _try(rot13_body)
    except Exception as exc:
        _debug_decode_failure("rot13_near_miss_body", exc, value=body)

    # Try interpreting body as hex and decoding
    hex_clean = body.replace(" ", "").replace("-", "")
    if hex_clean and all(ch in "0123456789abcdefABCDEF" for ch in hex_clean) and len(hex_clean) % 2 == 0:
        try:
            decoded = binascii.unhexlify(hex_clean).decode("utf-8", errors="ignore")
            _try(decoded)
        except Exception as exc:
            _debug_decode_failure("hex_near_miss_body", exc, value=body)

    # Try base64 decoding the body
    if body and all(ch.isalnum() or ch in "+/=" for ch in body):
        for variant in (body, body + "=", body + "=="):
            try:
                decoded = base64.b64decode(variant, validate=True).decode("utf-8", errors="ignore")
                _try(decoded)
            except Exception as exc:
                _debug_decode_failure("base64_near_miss_body", exc, value=body)

    # Latin-1 interpretation (for bytes > 127 that got mangled as UTF-8)
    try:
        raw_bytes = body.encode("latin-1")
        utf8_body = raw_bytes.decode("utf-8", errors="ignore")
        if utf8_body != body:
            _try(utf8_body)
    except (UnicodeDecodeError, UnicodeEncodeError) as exc:
        _debug_decode_failure("latin1_near_miss_body", exc, value=body)

    return candidates


__all__ = [
    "extract_flag_candidates",
    "encoding_cascade",
    "_bracket_span_candidates",
]
