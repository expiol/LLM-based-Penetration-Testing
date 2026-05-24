"""Shared constants used across all layers (plugins, agents, orchestrator).

This module is the single source of truth for regex patterns, false-positive
filters, and source-file extension sets.  It deliberately lives in the
``state`` package — the lowest layer everyone depends on — so the agent layer
(L3) and orchestrator layer (L4) don't need to reach into ``tools.plugins``
internals (L1) for shared values.
"""

from __future__ import annotations

import re

DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"

# ---------------------------------------------------------------------------
# Flag-detection regex patterns
# ---------------------------------------------------------------------------
#
# Single source of truth for the "flag shape".  All extraction, plausibility,
# and validation gates are built from these constants so they cannot drift
# apart.  The previous design had four independent regexes that disagreed on
# whether spaces were allowed in the body, which caused valid whitespace-bearing
# candidates to be dropped before validation.

#: Minimum prefix length: real CTF prefixes are ``flag``, ``ctf``, ``key``,
#: ``csaw``, ``nyu``, … all ≥ 2 chars.  1-char prefixes like ``t{pagination}``
#: and ``f{x}`` are CSS / template echoes, not flags.
FLAG_PREFIX_MIN_LEN = 2

#: Maximum prefix length.  This keeps flag extraction predictable on noisy
#: plaintext/ASCII-art output where a very long alnum run is followed by a
#: brace.  Real CTF prefixes are short; 64 leaves ample room for custom names.
FLAG_PREFIX_MAX_LEN = 64

#: Body character class for canonical flag extraction: printable ASCII
#: (space..tilde, 0x20-0x7E) excluding ``{`` and ``}`` so the regex doesn't
#: cross a brace boundary.  Equivalent to ``[ -z|~]``.
_FLAG_BODY_CLASS = r"[ -z|~]"

#: Min/max body length.  4 chars below = obvious noise, 200 above = pasted
#: paragraph.
FLAG_BODY_MIN_LEN = 4
FLAG_BODY_MAX_LEN = 200

FLAG_TOTAL_MAX_LEN = FLAG_PREFIX_MAX_LEN + FLAG_BODY_MAX_LEN + 2

#: Canonical flag pattern: ``prefix{body}`` where prefix is ≥2 alnum/_ chars
#: and body is printable ASCII (incl. space) excluding braces and newlines.
FLAG_PATTERN = re.compile(
    rf"(?<![A-Za-z0-9_])[A-Za-z0-9_]{{{FLAG_PREFIX_MIN_LEN},{FLAG_PREFIX_MAX_LEN}}}\{{{_FLAG_BODY_CLASS}{{{FLAG_BODY_MIN_LEN},{FLAG_BODY_MAX_LEN}}}\}}"
)

#: Strict full-match validation regex.  Same shape, anchored.
FLAG_PREFIX_SHAPE = re.compile(
    rf"^[A-Za-z0-9_]{{{FLAG_PREFIX_MIN_LEN},{FLAG_PREFIX_MAX_LEN}}}\{{{_FLAG_BODY_CLASS}{{{FLAG_BODY_MIN_LEN},{FLAG_BODY_MAX_LEN}}}\}}$"
)

# Non-bracket CTF flags: long, high-entropy tokens that appear in recovered
# plaintext without a ``prefix{...}`` wrapper.
FLAG_BARE_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}$")
PYTHON_EXCEPTION_TOKEN_RE = re.compile(
    r"^(?:[A-Z][A-Za-z0-9]*)+(?:Error|Exception|Warning)$"
)
ESCAPED_BYTE_RE = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0abfnrtv]")
ESCAPED_BYTE_BARE_PREFIX_RE = re.compile(r"^x[0-9a-fA-F]{2}[-_.]")
FLAG_BARE_TOKEN_MIN_ALNUM = 8
FLAG_BARE_TOKEN_MAX_SEPARATOR_RATIO = 0.35

#: Bracket span: a ``{...}`` substring with printable body, no nested braces.
#: Used by the secondary extractor when the canonical extractor finds no
#: candidates but tool output has free-floating bracket-wrapped content.
BRACKET_SPAN_PATTERN = re.compile(
    rf"\{{({_FLAG_BODY_CLASS}{{{FLAG_BODY_MIN_LEN},{FLAG_BODY_MAX_LEN}}})\}}"
)


# ---------------------------------------------------------------------------
# False-positive filter sets
# ---------------------------------------------------------------------------

#: Python introspection / debug tokens mistaken for flag prefixes when a
#: script echoes introspection output (e.g. ``repr{bytes...}``-style glue).
PYTHON_DUMP_PREFIX_DENYLIST: frozenset[str] = frozenset({
    "repr", "ascii", "vars", "locals", "globals", "getattr", "setattr",
    "hasattr", "super", "object",     "help",
})

#: Keyword prefixes that look like ``word{...}`` but are HTML/CSS/code tokens.
CODE_FALSE_POSITIVE_PREFIXES: frozenset[str] = frozenset({
    "html", "body", "div", "span", "input", "button", "textarea",
    "select", "label", "form", "table", "thead", "tbody", "tr", "td", "th",
    "ul", "ol", "li", "nav", "header", "footer", "section", "article",
    "aside", "main", "summary", "details", "dialog", "fieldset", "legend",
    "img", "video", "audio", "canvas", "svg", "path", "circle", "rect",
    "code", "pre", "blockquote", "cite", "abbr", "address", "figure",
    "figcaption", "picture", "source", "track", "embed", "object", "param",
    "var", "function", "return", "if", "else", "for", "while", "switch",
    "case", "class", "interface", "struct", "enum", "type", "export",
    "import", "from", "const", "let", "new", "delete", "typeof", "void",
    "null", "undefined", "true", "false", "try", "catch", "throw",
    "this", "self", "super", "extends", "implements", "abstract",
    "static", "final", "public", "private", "protected", "virtual",
    "override", "default", "break", "continue", "goto", "do", "elsif",
    "elif", "def", "lambda", "yield", "async", "await", "with",
    "create", "drop", "alter", "insert", "update", "select",
})

#: CSS property-value body pattern — rejects ``word{color: red; ...}`` shapes.
CSS_BODY_RE = re.compile(
    r"^[\s]*([a-z\-]+\s*:\s*[a-z0-9#%.\"', \-()]+\s*;?[\s]*)+$",
    re.IGNORECASE,
)

#: Python printf / format-debug fragments (e.g. ``seed:08x`` inside ``x{seed:08x}``).
FLAG_BODY_FORMAT_SPEC_RE = re.compile(
    r"[A-Za-z_]\w*:[0-9]*[xXdDuifeEgGF](?:\b|(?=\})|$)|(?::[0-9]+[xXdDuifeEgGF](?:\b|(?=\})|$))",
)

# Structured diagnostic bodies that bracket-span extraction must not wrap as
# flags, e.g. a tool result dict with command/stderr/returncode fields.
STRUCTURED_DIAGNOSTIC_BODY_RE = re.compile(
    r"['\"]?(?:command|error|exception|traceback|stderr|stdout|returncode|help_output)['\"]?\s*:",
    re.IGNORECASE,
)

# Python container/expression echoes that commonly appear when generated
# scripts print intermediate data structures instead of a recovered secret.
PYTHON_REPR_BODY_RE = re.compile(
    r"(^|\s|,)(?:['\"][^'\"]+['\"]|\d+)\s*:\s*[^,]+"
    r"|^['\"].*['\"]$"
    r"|['\"]\s*,\s*['\"]"
    r"|[\[\]]"
    r"|,\s*\([^)]*"
    r"|\([^)]*,[^)]*\)"
    r"|\b(?:os|sys|subprocess|socket|json|re)\."
    r"|\bif\b.+\belse\b"
    r"|\*\s*\d+",
    re.IGNORECASE,
)

#: Code-statement body pattern — rejects bodies that contain statement
#: terminators, function calls, or language operators that never appear in
#: real CTF flags (e.g. ``key{ return (bool) \Cookie::get(...); }``).
CODE_STATEMENT_BODY_RE = re.compile(
    r";|\breturn\b|\bfunction\b|=>|->|::",
)

#: Common template-echo bodies that CSS / HTML / Mustache produce.  Any
#: ``prefix{<noise>}`` whose body is one of these is unambiguously not a flag.
TEMPLATE_NOISE_BODIES: frozenset[str] = frozenset({
    "pagination", "link", "links", "count", "title", "description",
    "name", "value", "key", "thing", "tablename", "fieldname",
    "id", "type", "class", "label", "placeholder", "input", "output",
    "filepath", "filename", "path", "file", "content", "data",
    "text", "string", "result", "flag", "secret", "token", "hash",
    "variable", "param", "argument", "option", "config", "setting",
    "compressed", "decompressed", "standard", "non-standard",
    "metadata", "comment", "chunk", "chunks",
})

# Literal challenge descriptions often show examples like ``flag{....}`` or
# ``ctf{xxxx}``.  Those are format placeholders, not candidates worth sending
# to the validator.
PLACEHOLDER_FLAG_BODY_RE = re.compile(
    r"^(?:"
    r"\.+|\?+|\*+|#+|_+|-+"
    r"|x{4,}|X{4,}"
    r"|<[^{}]+>|\[[^\[\]{}]+\]"
    r")$"
)

FLAG_VALIDATION_SOURCE_NEEDLES: tuple[str, ...] = (
    "re.findall", "re.search", "re.match",
    "subprocess.", "os.system", "shell=true",
    "{thing}", "{tablename}", "{fieldname}",
    "{0}", "{1}", "{name}", "{flag}",
)
FLAG_BARE_TOKEN_NOISE_NEEDLES: tuple[str, ...] = (
    "no_flag_found", "noflagfound",
    "flag_not_found", "flag_not_recovered",
    "no_flag_recovered",
    "manual_review_required", "manual_review",
    "todo_replace_me", "your_flag_here", "insert_flag",
    "placeholder", "not_implemented",
)
FLAG_BARE_TOKEN_NOISE_WORDS: frozenset[str] = frozenset({
    "candidate", "candidates", "sequence", "sequences", "plaintext",
    "ciphertext", "decoded", "decrypted", "printable", "preview",
    "output", "result", "results", "matches", "pattern", "patterns",
    "little-endian", "big-endian", "native-endian", "little_endian",
    "big_endian", "native_endian", "endianness", "byteorder",
    "byte-order", "word-order", "xor-mode", "xor_mode",
    "decrypted.bin", "plaintext.bin", "output.bin", "candidate.bin",
    "result.bin", "decoded.bin",
})
FLAG_BARE_TOKEN_DESCRIPTOR_WORDS: frozenset[str] = frozenset({
    "ascii", "base64", "brace", "braces", "bracket", "bracketed",
    "candidate", "candidates", "common", "ctf", "decoded", "decrypted",
    "enclosed", "flag", "format", "hex", "long", "match", "matches",
    "output", "pattern", "plaintext", "recovered", "result", "search",
    "searched", "short", "string", "token", "tokens", "wrapped",
})

FLAG_BARE_TOKEN_FILE_EXTENSION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}$")
FLAG_BARE_TOKEN_FILE_STEMS: frozenset[str] = frozenset({
    "answer", "candidate", "cipher", "ciphertext", "data", "decoded",
    "decrypted", "encrypted", "flag", "input", "key", "output", "plain",
    "plaintext", "result", "secret", "solve",
})
FLAG_BARE_TOKEN_FILE_EXTENSIONS: frozenset[str] = frozenset({
    "7z", "bin", "bz2", "c", "cap", "csv", "dat", "db", "dec", "elf", "enc",
    "gz", "h", "hex", "jpg", "json", "log", "md", "out", "pcap", "pcapng",
    "pem", "png", "py", "sqlite", "sqlite3", "tar", "txt", "xz", "zip",
})
FLAG_BARE_TOKEN_VERSION_RE = re.compile(
    r"^[A-Za-z]{2,}[A-Za-z0-9_-]*\d+(?:[.-]\d+)+[A-Za-z0-9_-]*$"
)
FLAG_BARE_TOKEN_SERVICE_FINGERPRINT_RE = re.compile(
    r"^SF-Port\d+-TCP$",
    re.IGNORECASE,
)
FLAG_BARE_TOKEN_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
FLAG_BARE_TOKEN_LOWER_DOTTED_NAMESPACE_RE = re.compile(
    r"^(?:[a-z0-9-]{2,}\.)+[a-z][a-z0-9-]{1,}$"
)
FLAG_BARE_TOKEN_METADATA_NOISE: frozenset[str] = frozenset({
    "22-rdf-syntax-ns",
    "chromaticity",
    "com.adobe.xmp",
    "ctf_temp_dir",
    "ns.adobe.com",
    "rdf-syntax-ns",
})

#: Common CTF prefixes used for bracket-span extraction (see
#: :data:`BRACKET_SPAN_PATTERN`).  When extraction returns nothing but a
#: bracket span is present, we wrap the body with each of these and emit
#: them as candidates so the equality-validator can pick the right one.
COMMON_FLAG_PREFIXES: tuple[str, ...] = (
    "flag", "FLAG", "ctf", "CTF", "key", "KEY",
    "csaw", "CSAW", "nyu", "NYU",
)


# ---------------------------------------------------------------------------
# Plausibility helpers
# ---------------------------------------------------------------------------

def flag_prefix_shape(candidate: str) -> bool:
    """Return True for canonical ``prefix{body}`` shape without regex."""

    text = str(candidate or "").strip()
    if len(text) > FLAG_TOTAL_MAX_LEN:
        return False
    prefix, sep, body = text.partition("{")
    if not sep or not body.endswith("}"):
        return False
    body = body[:-1]
    if not (FLAG_PREFIX_MIN_LEN <= len(prefix) <= FLAG_PREFIX_MAX_LEN):
        return False
    if not (FLAG_BODY_MIN_LEN <= len(body) <= FLAG_BODY_MAX_LEN):
        return False
    if not all(ch.isalnum() or ch == "_" for ch in prefix):
        return False
    for ch in body:
        codepoint = ord(ch)
        if ch in "{}" or codepoint < 32 or codepoint > 126:
            return False
    return True


def bare_token_shape(candidate: str) -> bool:
    """Return True for long bare-token flag candidates without regex."""

    text = str(candidate or "").strip()
    if not (12 <= len(text) <= 200):
        return False
    if not text[0].isalnum():
        return False
    return all(ch.isalnum() or ch in "_.-" for ch in text)


def _python_exception_token(text: str) -> bool:
    if not text.endswith(("Error", "Exception", "Warning")):
        return False
    return text[:1].isupper() and text.replace("_", "").isalnum()


def _bare_token_file_name(text: str) -> bool:
    if "." not in text:
        return False
    stem, dot, ext = text.rpartition(".")
    if not stem or not dot:
        return False
    ext_lower = ext.lower()
    if not FLAG_BARE_TOKEN_FILE_EXTENSION_RE.fullmatch(ext_lower):
        return False
    stem_tail = stem.rsplit(".", 1)[-1].strip("._-").lower()
    if ext_lower in FLAG_BARE_TOKEN_FILE_EXTENSIONS:
        return all(ch.isalnum() or ch in "_.-" for ch in text)
    if stem_tail in FLAG_BARE_TOKEN_FILE_STEMS:
        return all(ch.isalnum() or ch in "_.-" for ch in text)
    return False


def _bare_token_descriptor_phrase(text: str) -> bool:
    if text != text.lower():
        return False
    if not any(separator in text for separator in "_.-"):
        return False
    parts = [part for part in re.split(r"[_.-]+", text) if part]
    if len(parts) < 2:
        return False
    return all(part in FLAG_BARE_TOKEN_DESCRIPTOR_WORDS for part in parts)


def _low_information_bare_token(text: str) -> bool:
    alnum_chars = [ch.lower() for ch in text if ch.isalnum()]
    if len(alnum_chars) < 12:
        return False

    distinct = len(set(alnum_chars))
    separators = len(text) - len(alnum_chars)
    if separators == 0 and distinct <= 3:
        return True

    longest_run = 1
    current_run = 1
    previous = alnum_chars[0]
    for ch in alnum_chars[1:]:
        if ch == previous:
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            previous = ch
            current_run = 1

    run_ratio = longest_run / len(alnum_chars)
    return separators == 0 and distinct <= 8 and longest_run >= 8 and run_ratio >= 0.30


def _known_nonflag_bare_token(text: str) -> bool:
    normalized = text.lower().strip("._-")
    if normalized in FLAG_BARE_TOKEN_METADATA_NOISE:
        return True
    if FLAG_BARE_TOKEN_UUID_RE.fullmatch(text):
        return True
    if text == text.lower() and FLAG_BARE_TOKEN_LOWER_DOTTED_NAMESPACE_RE.fullmatch(text):
        return True
    if FLAG_BARE_TOKEN_SERVICE_FINGERPRINT_RE.fullmatch(text):
        return True
    if FLAG_BARE_TOKEN_VERSION_RE.fullmatch(text):
        return True
    return False


def plausible_flag(candidate: str) -> bool:
    """Return True when *candidate* looks like a real CTF flag.

    Rejects HTML/CSS/code-keyword prefixes, single-character prefixes
    (``t{pagination}``), template-echo bodies (``flag{pagination}``),
    CSS-style bodies, and printf format-spec bodies.
    """
    prefix, sep, body = candidate.partition("{")
    if len(candidate) > FLAG_TOTAL_MAX_LEN:
        return False
    if not sep or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix or not body:
        return False
    if not (FLAG_PREFIX_MIN_LEN <= len(prefix) <= FLAG_PREFIX_MAX_LEN):
        return False
    if not (FLAG_BODY_MIN_LEN <= len(body) <= FLAG_BODY_MAX_LEN):
        return False
    if "(" in prefix or ")" in prefix:
        return False
    if prefix.lower() in PYTHON_DUMP_PREFIX_DENYLIST:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        return False
    if prefix.lower() in CODE_FALSE_POSITIVE_PREFIXES:
        return False
    if CSS_BODY_RE.match(body):
        return False
    if FLAG_BODY_FORMAT_SPEC_RE.search(body):
        return False
    stripped_body = body.strip()
    if not any(c.isalnum() for c in stripped_body):
        return False
    if PLACEHOLDER_FLAG_BODY_RE.fullmatch(stripped_body):
        return False
    if STRUCTURED_DIAGNOSTIC_BODY_RE.search(body):
        return False
    if PYTHON_REPR_BODY_RE.search(body):
        return False
    if CODE_STATEMENT_BODY_RE.search(body):
        return False
    if _noisy_short_flag_body(body):
        return False
    if stripped_body.lower() in TEMPLATE_NOISE_BODIES:
        return False
    return True


def _noisy_short_flag_body(body: str) -> bool:
    """Reject short binary/LSB fragments wrapped as flag bodies."""

    stripped = body.strip()
    if not stripped:
        return True
    uncommon_symbols = [
        ch for ch in stripped
        if not (ch.isalnum() or ch in {" ", "_", "-", "."})
    ]
    if "\\" in stripped:
        return True
    if uncommon_symbols:
        return len(stripped) < 16 or len(uncommon_symbols) / len(stripped) > 0.15
    if len(stripped) <= 5 and not any(ch.isdigit() for ch in stripped):
        separators = sum(1 for ch in stripped if not ch.isalnum())
        uppercase = sum(1 for ch in stripped if ch.isupper())
        if separators and uppercase >= 2:
            return True
    return False


def validatable_flag_candidate(candidate: str) -> bool:
    """Return True when a candidate is worth adding to run state."""

    text = (candidate or "").strip()
    if len(text) > FLAG_TOTAL_MAX_LEN:
        return False
    if flag_prefix_shape(text):
        lowered = text.lower()
        if any(needle in lowered for needle in FLAG_VALIDATION_SOURCE_NEEDLES):
            return False
        return plausible_flag(text)
    if bare_token_shape(text):
        if _python_exception_token(text):
            return False
        if ESCAPED_BYTE_BARE_PREFIX_RE.match(text):
            return False
        alnum = sum(1 for ch in text if ch.isalnum())
        separators = len(text) - alnum
        if alnum < FLAG_BARE_TOKEN_MIN_ALNUM:
            return False
        if separators / len(text) > FLAG_BARE_TOKEN_MAX_SEPARATOR_RATIO:
            return False
        lowered = text.lower()
        if any(needle in lowered for needle in FLAG_BARE_TOKEN_NOISE_NEEDLES):
            return False
        normalized = lowered.strip("._-")
        if normalized in FLAG_BARE_TOKEN_NOISE_WORDS:
            return False
        if _bare_token_descriptor_phrase(lowered):
            return False
        if _bare_token_file_name(text):
            return False
        if _known_nonflag_bare_token(text):
            return False
        if _low_information_bare_token(text):
            return False
        if text.endswith("..."):
            return False
        return True
    return False


def looks_like_escaped_byte_candidate(candidate: str) -> bool:
    """Return True for flag-shaped strings lifted from Python byte repr noise."""

    text = str(candidate or "").strip()
    if "{" not in text or not text.endswith("}"):
        return False
    _prefix, _sep, body = text.partition("{")
    body = body[:-1]
    if "\\x" in body:
        return True
    return len(ESCAPED_BYTE_RE.findall(body)) >= 2
