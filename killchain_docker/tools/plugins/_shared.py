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
    near_miss_flag,
    plausible_flag,
)
from killchain_docker.state.file_classification import SOURCE_EXTS as SOURCE_EXTENSIONS  # noqa: F401

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
_STRUCTURED_DIAGNOSTIC_BODY_RE = re.compile(
    r"['\"]?(?:command|error|exception|traceback|stderr|stdout|returncode|help_output)['\"]?\s*:",
    re.IGNORECASE,
)
_TEMPLATE_NOISE_BODIES = frozenset({
    "pagination", "link", "links", "count", "title", "description",
    "name", "value", "key", "thing", "tablename", "fieldname",
    "id", "type", "class", "label", "placeholder", "input", "output",
})
# ``flag{And yes the nsa can read this to}``-style spans appear in tool
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
    if _STRUCTURED_DIAGNOSTIC_BODY_RE.search(body):
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
    if _STRUCTURED_DIAGNOSTIC_BODY_RE.search(body):
        return False
    printable = sum(1 for c in body if 32 <= ord(c) <= 126)
    ratio = printable / len(body)
    return 0.70 <= ratio < 1.0

_LOCAL_CONTEXT_WINDOW = 200

def _bracket_span_candidates(text, flag_format_prefix=None, max_take=12):
    # Inline subprocess analogue of reasoning.flag._bracket_span_candidates.
    # Used as a fallback when the canonical extractor finds nothing but the
    # tool output contains free-floating ``{body}`` spans, e.g.
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


#: Shared target expansion block embedded verbatim in file-oriented plugin
#: SCRIPT strings. It accepts only standard metadata fields from callers; the
#: helper expands the values inside those fields into concrete readable files.
SHARED_FILE_TARGETS_SNIPPET = r"""
import atexit as _target_atexit
import fnmatch as _target_fnmatch
import gzip as _target_gzip
import shutil as _target_shutil
import tarfile as _target_tarfile
import tempfile as _target_tempfile
import zipfile as _target_zipfile
from pathlib import Path as _TargetPath, PurePosixPath as _TargetPurePosixPath

_TARGET_TEMP_DIRS = []
_TARGET_SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".cs", ".go", ".h", ".hpp", ".htm", ".html",
    ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql",
    ".sv", ".swift", ".tera", ".ts", ".tsx", ".v", ".xml", ".yaml", ".yml",
    ".json", ".md", ".txt", ".cfg", ".ini", ".toml",
}
_TARGET_PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap"}
_TARGET_DATABASE_SUFFIXES = {".db", ".sqlite", ".sqlite3"}
_TARGET_ARCHIVE_SUFFIXES = {".zip", ".tar", ".tgz", ".gz", ".7z", ".rar"}


def _target_cleanup():
    for temp_dir in _TARGET_TEMP_DIRS:
        _target_shutil.rmtree(temp_dir, ignore_errors=True)


_target_atexit.register(_target_cleanup)


def _target_safe_rel(value):
    rel = str(value or "").strip()
    if not rel:
        return ""
    rel = str(_TargetPurePosixPath(rel)).lstrip("./")
    if rel.startswith("/") or ".." in _TargetPurePosixPath(rel).parts:
        return ""
    return rel


def _target_kind_accepts(path, kind, exact=False):
    if exact:
        return True
    suffix = _TargetPath(str(path)).suffix.lower()
    if kind == "source":
        return suffix in _TARGET_SOURCE_SUFFIXES
    if kind == "pcap":
        return suffix in _TARGET_PCAP_SUFFIXES
    if kind == "database":
        return suffix in _TARGET_DATABASE_SUFFIXES
    if kind == "archive":
        return suffix in _TARGET_ARCHIVE_SUFFIXES
    return True


def _target_rel_display(path, root):
    try:
        return str(_TargetPath(path).resolve().relative_to(root))
    except Exception:
        return str(path)


def _target_add_file(out, seen, display, path, kind, exact=False, limit=100):
    if len(out) >= limit:
        return
    p = _TargetPath(path)
    if not p.is_file():
        return
    if not _target_kind_accepts(display, kind, exact=exact):
        return
    key = str(p.resolve())
    if key in seen:
        return
    seen.add(key)
    out.append({"display": str(display), "path": str(p)})


def _target_extract_archive_member(archive_path, member_name):
    temp_dir = _target_tempfile.mkdtemp(prefix="tool-target-")
    _TARGET_TEMP_DIRS.append(temp_dir)
    dest = _TargetPath(temp_dir) / _TargetPath(member_name).name
    suffix = archive_path.suffix.lower()
    if _target_zipfile.is_zipfile(archive_path):
        with _target_zipfile.ZipFile(archive_path) as zf:
            with zf.open(member_name) as src, open(dest, "wb") as dst:
                dst.write(src.read())
        return dest
    if _target_tarfile.is_tarfile(archive_path):
        with _target_tarfile.open(archive_path, "r:*") as tf:
            src = tf.extractfile(member_name)
            if src is None:
                return None
            with src, open(dest, "wb") as dst:
                dst.write(src.read())
        return dest
    if suffix == ".gz":
        with _target_gzip.open(archive_path, "rb") as src, open(dest, "wb") as dst:
            dst.write(src.read())
        return dest
    return None


def _target_archive_members(archive_path):
    if _target_zipfile.is_zipfile(archive_path):
        with _target_zipfile.ZipFile(archive_path) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield info.filename
        return
    if _target_tarfile.is_tarfile(archive_path):
        with _target_tarfile.open(archive_path, "r:*") as tf:
            for member in tf.getmembers():
                if member.isfile():
                    yield member.name
        return
    if archive_path.suffix.lower() == ".gz":
        yield archive_path.stem


def _resolve_file_targets(files_root, requested, max_files=12, kind=None):
    root = _TargetPath(files_root).resolve()
    out = []
    seen = set()
    limit = int(max_files)
    raw_targets = [str(item).strip() for item in (requested or []) if str(item).strip()]
    for raw in raw_targets:
        if len(out) >= limit:
            break
        archive_ref = ":" in raw and not raw.startswith("/") and "://" not in raw
        if archive_ref:
            archive_name, member_pattern = raw.split(":", 1)
            archive_rel = _target_safe_rel(archive_name)
            member_pattern = _target_safe_rel(member_pattern)
            if not archive_rel or not member_pattern:
                continue
            archive_path = (root / archive_rel).resolve()
            try:
                archive_path.relative_to(root)
            except ValueError:
                continue
            if not archive_path.is_file():
                continue
            exact_member = not any(ch in member_pattern for ch in "*?[")
            try:
                for member in _target_archive_members(archive_path):
                    member_rel = _target_safe_rel(member)
                    if not member_rel:
                        continue
                    if exact_member and member_rel != member_pattern:
                        continue
                    if not exact_member and not _target_fnmatch.fnmatch(member_rel, member_pattern):
                        continue
                    if not _target_kind_accepts(member_rel, kind, exact=exact_member):
                        continue
                    extracted = _target_extract_archive_member(archive_path, member_rel)
                    if extracted is not None:
                        _target_add_file(
                            out,
                            seen,
                            f"{archive_rel}:{member_rel}",
                            extracted,
                            kind,
                            exact=True,
                            limit=limit,
                        )
            except Exception:
                continue
            continue

        text = raw
        exact = not any(ch in text for ch in "*?[")
        if text.startswith(str(root) + "/"):
            text = text[len(str(root)) + 1 :]
        if text.startswith("./"):
            text = text[2:]

        candidates = []
        if exact:
            path = _TargetPath(text)
            if path.is_absolute():
                try:
                    resolved = path.resolve()
                    resolved.relative_to(root)
                except ValueError:
                    continue
                candidates = [resolved]
            else:
                safe = _target_safe_rel(text)
                if not safe:
                    continue
                candidates = [(root / safe).resolve()]
        else:
            safe = _target_safe_rel(text)
            if not safe:
                continue
            try:
                candidates = sorted(root.glob(safe))
            except Exception:
                candidates = []

        for path in candidates:
            if len(out) >= limit:
                break
            try:
                resolved = _TargetPath(path).resolve()
                resolved.relative_to(root)
            except Exception:
                continue
            if resolved.is_dir():
                for nested in sorted(p for p in resolved.rglob("*") if p.is_file()):
                    if len(out) >= limit:
                        break
                    _target_add_file(
                        out,
                        seen,
                        _target_rel_display(nested, root),
                        nested,
                        kind,
                        exact=False,
                        limit=limit,
                    )
            else:
                _target_add_file(
                    out,
                    seen,
                    _target_rel_display(resolved, root),
                    resolved,
                    kind,
                    exact=exact,
                    limit=limit,
                )
    return out
"""
