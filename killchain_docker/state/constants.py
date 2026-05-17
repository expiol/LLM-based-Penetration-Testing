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
# whether spaces were allowed in the body — and that disagreement is what
# silently dropped the `csawpad` answer (`key{And yes the nsa can read this
# to}`) before validation.

#: Minimum prefix length: real CTF prefixes are ``flag``, ``ctf``, ``key``,
#: ``csaw``, ``nyu``, … all ≥ 2 chars.  1-char prefixes like ``t{pagination}``
#: and ``f{x}`` are CSS / template echoes, not flags.
FLAG_PREFIX_MIN_LEN = 2

#: Body character class for canonical flag extraction: printable ASCII
#: (space..tilde, 0x20-0x7E) excluding ``{`` and ``}`` so the regex doesn't
#: cross a brace boundary.  Equivalent to ``[ -z|~]``.
_FLAG_BODY_CLASS = r"[ -z|~]"

#: Min/max body length.  4 chars below = obvious noise, 200 above = pasted
#: paragraph.
FLAG_BODY_MIN_LEN = 4
FLAG_BODY_MAX_LEN = 200

#: Canonical flag pattern: ``prefix{body}`` where prefix is ≥2 alnum/_ chars
#: and body is printable ASCII (incl. space) excluding braces and newlines.
FLAG_PATTERN = re.compile(
    rf"[A-Za-z0-9_]{{{FLAG_PREFIX_MIN_LEN},}}\{{{_FLAG_BODY_CLASS}{{{FLAG_BODY_MIN_LEN},{FLAG_BODY_MAX_LEN}}}\}}"
)

#: Strict full-match validation regex.  Same shape, anchored.
FLAG_PREFIX_SHAPE = re.compile(
    rf"^[A-Za-z0-9_]{{{FLAG_PREFIX_MIN_LEN},}}\{{{_FLAG_BODY_CLASS}{{{FLAG_BODY_MIN_LEN},{FLAG_BODY_MAX_LEN}}}\}}$"
)

# NYU-style non-bracket flags, e.g. CSAW 2013 stfu's
# ``STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME``.
FLAG_BARE_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}$")
PYTHON_EXCEPTION_TOKEN_RE = re.compile(
    r"^(?:[A-Z][A-Za-z0-9]*)+(?:Error|Exception|Warning)$"
)

#: Bracket span: a ``{...}`` substring with printable body, no nested braces.
#: Used as a fallback when the canonical extractor finds no candidates but
#: tool output has free-floating bracket-wrapped content (e.g. csawpad's
#: ``MY key for you is {And yes the nsa can read this to}``).
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

# Structured diagnostic bodies that bracket-span fallback must not wrap as
# flags, e.g. ``flag{'command': './stfu', 'error': '[Errno 2] ...'}``.
STRUCTURED_DIAGNOSTIC_BODY_RE = re.compile(
    r"['\"]?(?:command|error|exception|traceback|stderr|stdout|returncode|help_output)['\"]?\s*:",
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
})

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

#: Common CTF prefixes used for the bracket-span fallback (see
#: :data:`BRACKET_SPAN_PATTERN`).  When extraction returns nothing but a
#: bracket span is present, we wrap the body with each of these and emit
#: them as candidates so the equality-validator can pick the right one.
COMMON_FLAG_PREFIXES: tuple[str, ...] = (
    "flag", "FLAG", "ctf", "CTF", "key", "KEY",
    "csaw", "CSAW", "nyu", "NYU",
)


# ---------------------------------------------------------------------------
# Token normalization helpers (used by policy and stagnation detection)
# ---------------------------------------------------------------------------

import re as _re_tok

_TOKEN_SPLIT_RE = _re_tok.compile(r"[^a-z0-9]+")
_STOPWORDS = frozenset({
    "a", "an", "the", "and", "or", "of", "in", "on", "to", "for", "with",
    "from", "by", "into", "over", "under", "is", "are", "was", "were", "be",
    "as", "at", "this", "that", "these", "those", "it", "its", "we", "you",
    "they", "any", "all", "each", "some", "use", "using", "via",
})


def normalize_tokens(text: str) -> set[str]:
    """Return a set of meaningful tokens (lower-case, deduped, stop-filtered)."""
    if not text:
        return set()
    tokens = {tok for tok in _TOKEN_SPLIT_RE.split(text.lower()) if tok and len(tok) > 2}
    return tokens - _STOPWORDS


# ---------------------------------------------------------------------------
# Plausibility helpers
# ---------------------------------------------------------------------------

def plausible_flag(candidate: str) -> bool:
    """Return True when *candidate* looks like a real CTF flag.

    Rejects HTML/CSS/code-keyword prefixes, single-character prefixes
    (``t{pagination}``), template-echo bodies (``flag{pagination}``),
    CSS-style bodies, and printf format-spec bodies.
    """
    prefix, sep, body = candidate.partition("{")
    if not sep or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix or not body:
        return False
    if len(prefix) < FLAG_PREFIX_MIN_LEN:
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
    if STRUCTURED_DIAGNOSTIC_BODY_RE.search(body):
        return False
    if CODE_STATEMENT_BODY_RE.search(body):
        return False
    if body.lower().strip() in TEMPLATE_NOISE_BODIES:
        return False
    return True


def validatable_flag_candidate(candidate: str) -> bool:
    """Return True when a candidate is worth adding to run state."""

    text = (candidate or "").strip()
    if FLAG_PREFIX_SHAPE.fullmatch(text):
        lowered = text.lower()
        if any(needle in lowered for needle in FLAG_VALIDATION_SOURCE_NEEDLES):
            return False
        return plausible_flag(text)
    if FLAG_BARE_TOKEN_SHAPE.fullmatch(text):
        if PYTHON_EXCEPTION_TOKEN_RE.fullmatch(text):
            return False
        lowered = text.lower()
        if any(needle in lowered for needle in FLAG_BARE_TOKEN_NOISE_NEEDLES):
            return False
        return True
    return False
