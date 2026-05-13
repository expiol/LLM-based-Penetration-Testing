"""Plugin-internal helpers.

This module re-exports the canonical constants from
``killchain_docker.state.constants`` for backwards compatibility, and
owns the inline-script snippet that gets concatenated into the SCRIPT string
of plugins running in subprocesses.

The ``SHARED_FLAG_DETECTION_SNIPPET`` is a pure literal because it must be
shipped *as text* into the subprocess — there is no way to ``import`` it from
the spawned process.  All other definitions are simply forwarded so existing
imports keep working during refactors.
"""

from __future__ import annotations

# Re-export from the canonical home in state.constants.
from killchain_docker.state.constants import (  # noqa: F401
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
#: include this literal.  Keep this in sync with state.constants definitions:
#: prefix MUST be ≥2 alnum/_ chars, body is printable ASCII (incl. space)
#: with no control bytes, template-noise bodies and CSS/format-spec bodies
#: are rejected.
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
_FLAG_BODY_FORMAT_SPEC_RE = re.compile(
    r"[A-Za-z_]\w*:[0-9]*[xXdDuifeEgGF](?:\b|(?=\})|$)|(?::[0-9]+[xXdDuifeEgGF](?:\b|(?=\})|$))",
)
_TEMPLATE_NOISE_BODIES = frozenset({
    "pagination", "link", "links", "count", "title", "description",
    "name", "value", "key", "thing", "tablename", "fieldname",
    "id", "type", "class", "label", "placeholder", "input", "output",
})
# ``flag{And yes the nsa can read this to}``-style spans appear in solver
# output as free-floating ``{body}`` text without an immediate alnum prefix.
# Use this regex to mine those spans for the bracket-span fallback.
_BRACKET_SPAN_RE = re.compile(r"\{([ -z|~]{4,200})\}")
# Common CTF prefixes used to wrap the bracket-span body when no
# ``flag_format`` prefix is configured.  Match order is preferred order.
_COMMON_FLAG_PREFIXES = ("flag", "FLAG", "ctf", "CTF", "key", "KEY", "csaw", "CSAW", "nyu", "NYU")
# English glue words to filter out when lifting the immediate-preceding word
# as a candidate prefix (so "is{body}" / "my{body}" don't crowd "key{body}").
_BRACKET_SPAN_NOISY_PREFIXES = frozenset({
    "is", "are", "was", "were", "be", "been", "being",
    "the", "a", "an", "this", "that", "these", "those",
    "in", "on", "at", "by", "to", "of", "for", "with", "as",
    "and", "or", "but", "so", "yet", "if", "else", "then",
    "you", "i", "we", "they", "he", "she", "it",
    "my", "your", "our", "their", "his", "her", "its",
    "got", "get", "found", "see", "saw", "have", "has", "had",
    "value", "result", "answer", "output", "input", "data",
})
_PYTHON_DUMP_PREFIX_DENYLIST = frozenset({
    "repr", "ascii", "vars", "locals", "globals", "getattr", "setattr",
    "hasattr", "super", "object", "help",
})

def _plausible_flag(m):
    prefix, sep, body = m.partition("{")
    if not sep or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix or not body:
        return False
    if len(prefix) < 2:
        return False
    if "(" in prefix or ")" in prefix:
        return False
    if prefix.lower() in _PYTHON_DUMP_PREFIX_DENYLIST:
        return False
    if any(ord(c) < 32 or ord(c) == 127 for c in body):
        return False
    if prefix.lower() in _CODE_FALSE_POSITIVE_PREFIXES:
        return False
    if _CSS_BODY_RE.match(body):
        return False
    if _FLAG_BODY_FORMAT_SPEC_RE.search(body):
        return False
    if body.lower().strip() in _TEMPLATE_NOISE_BODIES:
        return False
    return True

def _near_miss_flag(m):
    prefix, sep, body = m.partition("{")
    if not sep or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix or not body or len(prefix) < 2:
        return False
    if _FLAG_BODY_FORMAT_SPEC_RE.search(body):
        return False
    printable = sum(1 for c in body if 32 <= ord(c) <= 126)
    ratio = printable / len(body)
    return 0.70 <= ratio < 1.0

_LOCAL_CONTEXT_WINDOW = 200

def _bracket_span_candidates(text, flag_format_prefix=None, max_take=12):
    # Inline subprocess analogue of agents._helpers.flag._bracket_span_candidates.
    # Used as a fallback when the canonical extractor finds nothing but the
    # solver output contains free-floating ``{body}`` spans, e.g.
    # ``MY key for you is {And yes the nsa can read this to}``.
    if not text:
        return []
    out = []
    seen_bodies = set()
    for match in _BRACKET_SPAN_RE.finditer(text):
        body = match.group(1)
        if body in seen_bodies:
            continue
        seen_bodies.add(body)
        prefixes = []
        # 1. Configured flag_format prefix wins.
        if flag_format_prefix:
            cleaned = flag_format_prefix.strip()
            if cleaned and all(c.isalnum() or c == "_" for c in cleaned):
                prefixes.append(cleaned)
        # 2. Common CTF prefixes that ALSO appear in the local context
        #    (within _LOCAL_CONTEXT_WINDOW chars before the bracket) get
        #    top priority — narrative output often spells out the prefix.
        local = text[max(0, match.start() - _LOCAL_CONTEXT_WINDOW): match.start()]
        local_lower = local.lower()
        for prefix in _COMMON_FLAG_PREFIXES:
            if re.search(r"\b" + re.escape(prefix.lower()) + r"\b", local_lower):
                if prefix not in prefixes:
                    prefixes.append(prefix)
        # 3. Remaining common prefixes as backup.
        for prefix in _COMMON_FLAG_PREFIXES:
            if prefix not in prefixes:
                prefixes.append(prefix)
        # 4. Lift the alnum word immediately preceding the bracket if it
        #    isn't an English glue word.
        word = re.search(r"([A-Za-z0-9_]{2,})\s*[^A-Za-z0-9_{}]*$", local)
        if word:
            tok = word.group(1)
            if tok.lower() not in _BRACKET_SPAN_NOISY_PREFIXES and tok not in prefixes:
                prefixes.append(tok)
        for prefix in prefixes:
            cand = prefix + "{" + body + "}"
            if cand in out:
                continue
            if not _plausible_flag(cand):
                continue
            out.append(cand)
            if len(out) >= max_take:
                return out
    return out
"""
