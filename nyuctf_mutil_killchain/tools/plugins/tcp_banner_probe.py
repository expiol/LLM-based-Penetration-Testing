"""TCP service banner collection tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "tcp_banner_probe"

SCRIPT = r"""
import json
import re
import socket
import sys

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
hostname = payload.get("hostname") or asset_id
ports = payload.get("ports") or []
timeout_s = int(payload.get("timeout_s", 30))

records = []
banner_hits = {}
flag_candidates = []
responsive_ports = []

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

http_ports = {80, 443, 8000, 8080, 8443, 8888, 3000, 5000}

for raw_port in ports[:16]:
    try:
        port = int(raw_port)
    except Exception:
        continue

    try:
        with socket.create_connection((hostname, port), timeout=min(3.0, timeout_s)) as sock:
            sock.settimeout(1.5)
            chunks = []
            try:
                data = sock.recv(512)
                if data:
                    chunks.append(data)
            except Exception:
                pass

            if not chunks:
                try:
                    if port in http_ports:
                        sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {hostname}\r\n\r\n".encode("utf-8"))
                    else:
                        sock.sendall(b"\r\n")
                    data = sock.recv(512)
                    if data:
                        chunks.append(data)
                except Exception:
                    pass

            banner = b"".join(chunks).decode("utf-8", errors="ignore").strip()
            if banner:
                responsive_ports.append(port)
                banner_hits[str(port)] = banner[:240]
                for flag in flag_re.findall(banner):
                    if not _plausible_flag(flag):
                        continue
                    if flag not in flag_candidates:
                        flag_candidates.append(flag)
    except Exception:
        continue

records.append({
    "type": "summary",
    "text": (
        f"TCP banner probe completed for {hostname}: "
        f"{len(responsive_ports)} responsive port(s), {len(flag_candidates)} flag candidate(s)."
    ),
})

if banner_hits:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-service-banners",
        "title": "Service banners captured from exposed ports",
        "severity": "medium",
        "description": f"Captured banner or greeting text from {len(banner_hits)} exposed port(s) on {hostname}.",
        "asset_refs": [asset_id],
        "evidence_refs": [f"{hostname}:{port}" for port in list(banner_hits.keys())[:8]],
        "metadata": {"source": "tcp_banner_probe", "banner_hits": banner_hits},
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": f"finding-{asset_id}-banner-flags",
        "title": "Flag-like token found in service banner",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from service banner content.",
        "asset_refs": [asset_id],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "tcp_banner_probe", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "hostname": hostname,
    "responsive_ports": responsive_ports,
    "banner_hits": banner_hits,
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Inspect banner text for challenge hints, protocols, or prompt strings.",
        "Use the observed protocol greeting to drive the next service interaction.",
        "Validate any recovered flag-like token before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "hostname": request.metadata.get("hostname"),
        "ports": request.metadata.get("ports", []),
        "timeout_s": request.timeout_s,
    }
    if not payload["hostname"]:
        raise ToolExecutionError("tcp_banner_probe requires metadata.hostname")
    return ["-c", SCRIPT, json.dumps(payload)]
