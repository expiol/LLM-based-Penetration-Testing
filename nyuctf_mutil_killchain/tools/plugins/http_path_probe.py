"""HTTP path probing tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "http_path_probe"

SCRIPT = r"""
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlparse

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
base_url = payload.get("base_url")
paths = payload.get("paths") or []
timeout_s = int(payload.get("timeout_s", 30))

records = []
path_results = []
flag_candidates = []
interesting_paths = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
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

title_re = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

if not base_url:
    records.append({"type": "summary", "text": "HTTP path probe skipped: base_url not provided."})
else:
    parsed = urlparse(base_url)
    ctx = None
    if parsed.scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    normalized_paths = []
    for path in paths[:20]:
        path = str(path).strip()
        if not path:
            continue
        if path.startswith(("http://", "https://")):
            normalized_paths.append(path)
        else:
            normalized_paths.append(urljoin(base_url.rstrip("/") + "/", path.lstrip("/")))
    normalized_paths = list(dict.fromkeys(normalized_paths))

    for probe_url in normalized_paths:
        status = None
        title = None
        body = ""
        try:
            req = urllib.request.Request(
                probe_url,
                headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)"},
            )
            open_args = {"timeout": min(8, timeout_s)}
            if ctx is not None:
                open_args["context"] = ctx
            with urllib.request.urlopen(req, **open_args) as resp:
                status = resp.status
                body = resp.read(4096).decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = exc.read(2048).decode("utf-8", errors="ignore")
            except Exception:
                body = ""
        except Exception as exc:
            records.append({"type": "note", "text": f"HTTP probe failed for {probe_url}: {type(exc).__name__}: {exc}"})
            continue

        title_match = title_re.search(body)
        if title_match:
            title = " ".join(title_match.group(1).split())[:120]
        for flag in flag_re.findall(body):
            if not _plausible_flag(flag):
                continue
            if flag not in flag_candidates:
                flag_candidates.append(flag)
        if status in {200, 401, 403}:
            interesting_paths.append(probe_url)
        path_results.append({
            "url": probe_url,
            "status": status,
            "title": title,
            "body_preview": body[:240],
        })

    records.append({
        "type": "summary",
        "text": (
            f"HTTP path probe completed for {base_url}: "
            f"{len(interesting_paths)} interesting path(s), {len(flag_candidates)} flag candidate(s)."
        ),
    })

    if interesting_paths:
        records.append({
            "type": "finding",
            "finding_id": f"finding-{asset_id}-path-probe",
            "title": "Interesting application paths responded",
            "severity": "medium",
            "description": f"{len(interesting_paths)} application path(s) responded with HTTP 200/401/403.",
            "asset_refs": [asset_id],
            "evidence_refs": interesting_paths[:8],
            "metadata": {"source": "http_path_probe", "path_results": path_results[:20]},
        })

    if flag_candidates:
        records.append({
            "type": "finding",
            "finding_id": f"finding-{asset_id}-path-flags",
            "title": "Flag-like token found while probing application paths",
            "severity": "high",
            "description": f"Recovered {len(flag_candidates)} flag candidate(s) from probed application paths.",
            "asset_refs": [asset_id],
            "evidence_refs": flag_candidates[:5],
            "metadata": {"source": "http_path_probe", "flag_candidates": flag_candidates[:10]},
        })

    records.append({
        "type": "output_context",
        "base_url": base_url,
        "path_results": path_results[:20],
        "interesting_paths": interesting_paths[:20],
        "flag_candidates": flag_candidates[:10],
        "manual_checks": [
            "Inspect 200/401/403 endpoints for auth bypass, debug interfaces, or hidden workflows.",
            "Cross-check source-derived paths against live behavior differences.",
            "Validate any recovered flag-like token before submission.",
        ],
    })

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "base_url": request.metadata.get("base_url"),
        "paths": request.metadata.get("paths", []),
        "timeout_s": request.timeout_s,
    }
    if not payload["base_url"]:
        raise ToolExecutionError("http_path_probe requires metadata.base_url")
    return ["-c", SCRIPT, json.dumps(payload)]
