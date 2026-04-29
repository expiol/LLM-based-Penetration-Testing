"""Shared constants used across all layers (plugins, agents, orchestrator).

This module is the single source of truth for regex patterns, false-positive
filters, and source-file extension sets.  It deliberately lives in the
``state`` package — the lowest layer everyone depends on — so the agent layer
(L3) and orchestrator layer (L4) don't need to reach into ``tools.plugins``
internals (L1) for shared values.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Flag-detection regex patterns
# ---------------------------------------------------------------------------

#: Canonical flag pattern: ``prefix{body}`` with ASCII-only printable body.
FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")

#: Same shape but allows non-printable characters (garbled decrypt).
NEAR_MISS_FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]{2,}\{[^\n]{4,200}\}")


# ---------------------------------------------------------------------------
# False-positive filter sets
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Source-file extension sets
# ---------------------------------------------------------------------------

#: Extensions that indicate human-readable source code worth reviewing.
SOURCE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".rb", ".pl", ".sh", ".c", ".cpp", ".h", ".java",
    ".php", ".go", ".rs", ".sage", ".txt", ".md", ".yml", ".yaml",
    ".json", ".xml", ".html", ".css", ".sql", ".lua", ".r",
})


# ---------------------------------------------------------------------------
# Plausibility helpers
# ---------------------------------------------------------------------------

def plausible_flag(candidate: str) -> bool:
    """Return True when *candidate* looks like a real CTF flag.

    Rejects HTML/CSS/code-keyword prefixes and CSS-style bodies.
    """
    prefix, _, body = candidate.partition("{")
    body = body.rstrip("}")
    if not prefix or not body:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        return False
    if prefix.lower() in CODE_FALSE_POSITIVE_PREFIXES:
        return False
    if CSS_BODY_RE.match(body):
        return False
    return True


def near_miss_flag(candidate: str) -> bool:
    """Return True when *candidate* has flag shape but garbled (non-printable) bytes."""
    prefix, _, body = candidate.partition("{")
    body = body.rstrip("}")
    if not prefix or not body or len(prefix) < 2:
        return False
    printable = sum(1 for c in body if 32 <= ord(c) <= 126)
    if not body:
        return False
    ratio = printable / len(body)
    return 0.70 <= ratio < 1.0
