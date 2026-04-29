"""Plugin-internal helpers.

This module re-exports the canonical constants from
``nyuctf_mutil_killchain.state.constants`` for backwards compatibility, and
owns the inline-script snippet that gets concatenated into the SCRIPT string
of plugins running in subprocesses.

The ``SHARED_FLAG_DETECTION_SNIPPET`` is a pure literal because it must be
shipped *as text* into the subprocess — there is no way to ``import`` it from
the spawned process.  All other definitions are simply forwarded so existing
imports keep working during refactors.
"""

from __future__ import annotations

# Re-export from the canonical home in state.constants.
from nyuctf_mutil_killchain.state.constants import (  # noqa: F401
    CODE_FALSE_POSITIVE_PREFIXES,
    CSS_BODY_RE,
    FLAG_PATTERN,
    NEAR_MISS_FLAG_PATTERN,
    SOURCE_EXTENSIONS,
    near_miss_flag,
    plausible_flag,
)

#: The shared flag-detection block embedded verbatim in plugin SCRIPT strings.
#: Plugins that need flag/near-miss detection inside their subprocess script
#: include this literal.  Keep this in sync with state.constants definitions.
SHARED_FLAG_DETECTION_SNIPPET = r"""
_CODE_FALSE_POSITIVE_PREFIXES = frozenset({
    "html", "body", "div", "span", "input", "button", "textarea",
    "select", "label", "form", "table", "thead", "tbody", "tr", "td", "th",
    "ul", "ol", "li", "nav", "header", "footer", "section", "article",
    "aside", "main", "summary", "details", "dialog", "fieldset", "legend",
    "img", "video", "audio", "canvas", "svg", "path", "circle", "rect",
    "code", "pre", "blockquote", "cite", "abbr", "address", "figure",
    "var", "function", "return", "if", "else", "for", "while", "switch",
    "case", "class", "interface", "struct", "enum", "type", "export",
    "import", "from", "const", "let", "new", "delete", "typeof", "void",
    "null", "undefined", "true", "false", "try", "catch", "throw",
    "this", "self", "super", "def", "lambda", "yield", "async", "await",
    "create", "drop", "alter", "insert", "update", "select",
})
_CSS_BODY_RE = re.compile(
    r"^[\s]*([a-z\-]+\s*:\s*[a-z0-9#%.\"', \-()]+\s*;?[\s]*)+$",
    re.IGNORECASE,
)

def _plausible_flag(m):
    prefix, _, body = m.partition("{")
    body = body.rstrip("}")
    if not prefix or not body:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        return False
    if prefix.lower() in _CODE_FALSE_POSITIVE_PREFIXES:
        return False
    if _CSS_BODY_RE.match(body):
        return False
    return True

def _near_miss_flag(m):
    prefix, _, body = m.partition("{")
    body = body.rstrip("}")
    if not prefix or not body or len(prefix) < 2:
        return False
    printable = sum(1 for c in body if 32 <= ord(c) <= 126)
    if len(body) == 0:
        return False
    ratio = printable / len(body)
    return 0.70 <= ratio < 1.0
"""
