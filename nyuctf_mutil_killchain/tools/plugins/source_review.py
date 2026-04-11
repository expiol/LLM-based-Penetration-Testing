"""Source code review tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "source_review"

SCRIPT = r"""
import gzip
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
source_files = payload.get("source_files") or []
max_files = int(payload.get("max_files", 12))

records = []
route_hits = []
secret_hits = []
flag_candidates = []
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
route_re = re.compile(r"[\"'](/[^\"'\\s]{1,120})[\"']")

_FP_PREFIXES = frozenset({
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
    "create", "drop", "alter", "insert", "update",
})
_CSS_BODY = re.compile(
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
    if prefix.lower() in _FP_PREFIXES:
        return False
    if _CSS_BODY.match(body):
        return False
    return True


def read_source_entry(entry):
    relpath = str(entry).strip()
    if not relpath:
        return None, None

    direct_path = files_root / relpath
    if direct_path.is_file():
        try:
            return relpath, direct_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return relpath, None

    archive_name, sep, member_name = relpath.partition(":")
    if not sep or not member_name:
        return relpath, None

    archive_path = files_root / archive_name
    if not archive_path.is_file():
        return relpath, None

    normalized_member = str(PurePosixPath(member_name)).lstrip("./")
    suffix = archive_path.suffix.lower()

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as zf:
                with zf.open(normalized_member) as fh:
                    return relpath, fh.read().decode("utf-8", errors="ignore")
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as tf:
                extracted = tf.extractfile(normalized_member)
                if extracted is None:
                    return relpath, None
                return relpath, extracted.read().decode("utf-8", errors="ignore")
        if suffix == ".gz" and normalized_member == archive_path.stem:
            with gzip.open(archive_path, "rb") as fh:
                return relpath, fh.read().decode("utf-8", errors="ignore")
    except Exception:
        return relpath, None

    return relpath, None

for relpath in source_files[:max_files]:
    inspected_path, content = read_source_entry(relpath)
    if not inspected_path or content is None:
        continue
    inspected.append(inspected_path)

    for route in route_re.findall(content):
        if route not in route_hits and any(token in route.lower() for token in ("admin", "login", "upload", "debug", "api", "flag")):
            route_hits.append(route)

    lowered = content.lower()
    if any(token in lowered for token in ("password", "secret", "token", "api_key", "apikey", "bearer ", "authorization")):
        secret_hits.append(relpath)

    for flag in flag_re.findall(content):
        if flag not in flag_candidates and _plausible_flag(flag):
            flag_candidates.append(flag)

records.append({
    "type": "summary",
    "text": (
        f"Source review completed for {len(inspected)} file(s): "
        f"{len(route_hits)} interesting route(s), {len(secret_hits)} secret-bearing file(s), "
        f"{len(flag_candidates)} flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-source-review",
    "title": "Bundled source files reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} bundled source artifact(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "source_review", "inspected": inspected},
})

if route_hits:
    records.append({
        "type": "finding",
        "finding_id": "finding-source-routes",
        "title": "Interesting routes discovered in source artifacts",
        "severity": "medium",
        "description": f"Recovered {len(route_hits)} potentially sensitive route(s) from bundled source files.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": route_hits[:8],
        "metadata": {"source": "source_review", "routes": route_hits[:20]},
    })

if secret_hits:
    records.append({
        "type": "finding",
        "finding_id": "finding-source-secrets",
        "title": "Source files contain secret-like content",
        "severity": "medium",
        "description": f"Detected secret-bearing content in {len(secret_hits)} source file(s).",
        "asset_refs": ["challenge-files"],
        "evidence_refs": secret_hits[:8],
        "metadata": {"source": "source_review", "secret_files": secret_hits[:20]},
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-source-flags",
        "title": "Flag-like token found in source artifacts",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from bundled source files.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "source_review", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_sources": inspected,
    "interesting_routes": route_hits[:20],
    "secret_files": secret_hits[:20],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Compare recovered routes against the live target surface.",
        "Review secret-bearing files for credentials or debug toggles.",
        "Validate any flag-like token before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "source_files": request.metadata.get("source_files", []),
        "max_files": request.metadata.get("max_files", 12),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
