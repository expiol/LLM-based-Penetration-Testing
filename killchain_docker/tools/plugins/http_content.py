"""HTTP body, form, and link review tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionError, ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FLAG_DETECTION_SNIPPET

TOOL_NAME = "local_http_content"

_SCRIPT_HEADER = r"""
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
base_url = payload["base_url"]
timeout_s = int(payload.get("timeout_s", 15))
parsed_url = urlparse(base_url)

records = []
notes_list = []
keywords = set()
interesting_links = []
potential_flags = []
forms = []
links = []
body_text = ""
title = ""
content_type = ""
http_status = None
flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
"""

_SCRIPT_BODY = r"""
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_title = False
        self.title_parts = []
        self.links = []
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "a":
            href = attrs.get("href")
            if href:
                self.links.append(href)
        elif tag == "form":
            self.current_form = {
                "action": attrs.get("action") or "",
                "method": (attrs.get("method") or "get").lower(),
                "enctype": (attrs.get("enctype") or "application/x-www-form-urlencoded").lower(),
                "inputs": [],
            }
        elif tag == "input" and self.current_form is not None:
            name = attrs.get("name") or attrs.get("id") or ""
            input_type = (attrs.get("type") or "text").lower()
            if name or input_type:
                self.current_form["inputs"].append({"name": name, "type": input_type})

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False
        elif tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


ctx = None
if parsed_url.scheme == "https":
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

try:
    req = urllib.request.Request(
        base_url,
        headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)"},
        method="GET",
    )
    open_args = {"timeout": timeout_s}
    if ctx is not None:
        open_args["context"] = ctx
    with urllib.request.urlopen(req, **open_args) as resp:
        http_status = resp.status
        content_type = resp.headers.get("Content-Type", "")
        raw = resp.read(200000)
        body_text = raw.decode("utf-8", errors="replace")
except urllib.error.HTTPError as exc:
    http_status = exc.code
    content_type = exc.headers.get("Content-Type", "") if exc.headers else ""
    body_text = exc.read(200000).decode("utf-8", errors="replace")
    notes_list.append(f"GET returned HTTP {exc.code}")
except Exception as exc:
    notes_list.append(f"GET failed for {base_url}: {type(exc).__name__}: {exc}")

if body_text:
    parser = PageParser()
    try:
        parser.feed(body_text)
    except Exception as exc:
        notes_list.append(f"HTML parsing error: {type(exc).__name__}: {exc}")
    title = " ".join(part.strip() for part in parser.title_parts if part.strip())[:200]
    forms = parser.forms[:10]
    links = parser.links[:30]

    lowered_body = body_text.lower()
    for keyword in ("login", "register", "signup", "upload", "admin", "debug", "flag", "api", "swagger", "graphql"):
        if keyword in lowered_body:
            keywords.add(keyword)

    static_suffixes = (
        ".css",
        ".js",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".woff",
        ".woff2",
        ".ttf",
        ".map",
    )
    for href in links:
        absolute = urljoin(base_url, href)
        lowered = absolute.lower()
        parsed_link = urlparse(absolute)
        path = parsed_link.path.lower()
        same_origin = (
            not parsed_link.netloc
            or (
                parsed_link.scheme == parsed_url.scheme
                and parsed_link.netloc == parsed_url.netloc
            )
        )
        script_like_path = path.endswith((".pl", ".cgi", ".php", ".asp", ".aspx", ".jsp"))
        dynamic_hint = any(
            token in lowered
            for token in ("login", "register", "upload", "admin", "debug", "swagger", "graphql", "api", "cgi-bin")
        )
        looks_actionable = (
            same_origin
            and path not in {"", "/"}
            and not path.endswith(static_suffixes)
            and (dynamic_hint or script_like_path or "?" in absolute or path.count("/") >= 2)
        )
        if looks_actionable:
            if absolute not in interesting_links:
                interesting_links.append(absolute)

    potential_flags = list(dict.fromkeys(flag_re.findall(body_text)))[:5]

records.append({
    "type": "summary",
    "text": (
        f"HTTP content review for {base_url}: "
        f"{len(forms)} form(s), {len(interesting_links)} interesting link(s), "
        f"{len(potential_flags)} flag candidate(s)."
    ),
})

if forms:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-page-forms",
        "title": "Interactive HTML forms discovered",
        "severity": "medium",
        "description": f"Found {len(forms)} HTML form(s) on {base_url}.",
        "asset_refs": [asset_id],
        "evidence_refs": [base_url],
        "metadata": {"source": "http_content_probe", "forms": forms},
    })

if interesting_links:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-interesting-links",
        "title": "Interesting web routes exposed",
        "severity": "medium",
        "description": f"Discovered {len(interesting_links)} interesting route(s) on {base_url}.",
        "asset_refs": [asset_id],
        "evidence_refs": interesting_links[:5],
        "metadata": {"source": "http_content_probe", "interesting_links": interesting_links[:15]},
    })

if potential_flags:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-potential-flags",
        "title": "Flag-like token observed in response body",
        "severity": "high",
        "description": f"Recovered {len(potential_flags)} flag candidate(s) from {base_url}.",
        "asset_refs": [asset_id],
        "evidence_refs": potential_flags,
        "metadata": {"source": "http_content_probe", "potential_flags": potential_flags},
    })

for note in notes_list:
    records.append({"type": "note", "text": note})

records.append({
    "type": "output_context",
    "http_status": http_status,
    "content_type": content_type,
    "title": title,
    "links": links[:20],
    "interesting_links": interesting_links[:10],
    "forms": forms,
    "keywords": sorted(keywords),
    "potential_flags": potential_flags,
    "body_preview": body_text[:1500],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""

SCRIPT = _SCRIPT_HEADER + SHARED_FLAG_DETECTION_SNIPPET + _SCRIPT_BODY


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "base_url": request.metadata.get("base_url"),
        "timeout_s": request.timeout_s,
    }
    if not payload["base_url"]:
        raise ToolExecutionError("local_http_content requires metadata.base_url")
    return ["-c", SCRIPT, json.dumps(payload)]
