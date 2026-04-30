"""Flag-shape extraction and decoding heuristics for worker output."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from nyuctf_mutil_killchain.state.constants import (
    CODE_FALSE_POSITIVE_PREFIXES,
    CSS_BODY_RE,
    FLAG_PATTERN,
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


def _looks_like_plausible_flag(candidate: str) -> bool:
    """Filter out obvious garbage from flag candidate extraction.

    Real flags are printable ASCII with only minimal control chars.
    Garbage like ``boo{xFpd]=}`` or ``A{h;~chPtf`m}`` can slip through
    the raw regex but fail basic plausibility checks.
    Also rejects CSS selectors (``summary{display:block}``),
    code constructs (``function{...}``), and SQL patterns.
    """
    if not candidate or len(candidate) < 4:
        return False
    prefix, _, body = candidate.partition("{")
    if not body or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix.isalnum() and not all(c.isalnum() or c == "_" for c in prefix):
        return False
    if len(prefix) < 2:
        return False
    printable_count = sum(1 for ch in body if 32 <= ord(ch) <= 126)
    if not body or printable_count / len(body) < 0.90:
        return False
    control_count = sum(1 for ch in body if ord(ch) < 32 or ord(ch) == 127)
    if control_count > 0:
        return False

    if prefix.lower() in CODE_FALSE_POSITIVE_PREFIXES:
        return False
    if CSS_BODY_RE.match(body):
        return False
    if re.match(r"^[\s;,]+$", body):
        return False

    return True


def extract_flag_candidates(*values: str | None) -> list[str]:
    """Extract unique flag-like tokens from the supplied strings.

    In addition to direct regex matches, attempts base64, hex, and ROT13
    decoding on long encoded-looking blobs.  Applies plausibility filtering
    to reject garbage matches that slip through the raw regex.
    """

    candidates: list[str] = []
    for value in values:
        if not value:
            continue
        for match in FLAG_PATTERN.findall(value):
            if match not in candidates and _looks_like_plausible_flag(match):
                candidates.append(match)
        for blob in _BASE64_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                if decoded not in candidates and _looks_like_plausible_flag(decoded):
                    candidates.append(decoded)
        for blob in _HEX_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                if decoded not in candidates and _looks_like_plausible_flag(decoded):
                    candidates.append(decoded)
    return candidates
