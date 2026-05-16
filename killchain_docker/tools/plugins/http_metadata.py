"""HTTP metadata collection tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionError, ToolExecutionRequest

TOOL_NAME = "local_http_metadata"

SCRIPT = r"""
import json
import ssl
import sys
import socket
import urllib.request
import urllib.error
from urllib.parse import urlparse

payload = json.loads(sys.argv[1])
asset_id = payload.get("asset_id", "asset")
base_url = payload["base_url"]
timeout_s = int(payload.get("timeout_s", 10))
parsed_url = urlparse(base_url)
hostname = payload.get("hostname") or parsed_url.hostname or asset_id
port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

records = []
services = []
tech_tags = set()
security_issues = []
notes_list = []

ip_address = None
try:
    ip_address = socket.gethostbyname(hostname)
except socket.gaierror as exc:
    notes_list.append(f"DNS resolution failed for {hostname}: {exc}")

http_status = None
headers_dict = {}
try:
    ctx = None
    if parsed_url.scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(
        base_url,
        headers={"User-Agent": "Mozilla/5.0 (autopentest-scanner/0.1)"},
        method="HEAD",
    )
    open_args = {"timeout": timeout_s}
    if ctx is not None:
        open_args["context"] = ctx
    with urllib.request.urlopen(req, **open_args) as resp:
        http_status = resp.status
        headers_dict = dict(resp.headers)
except urllib.error.HTTPError as exc:
    http_status = exc.code
    headers_dict = dict(exc.headers) if exc.headers else {}
except urllib.error.URLError as exc:
    notes_list.append(f"HTTP request failed for {base_url}: {exc.reason}")
except Exception as exc:
    notes_list.append(f"HTTP probe error ({type(exc).__name__}): {exc}")

hdr = {k.lower(): v for k, v in headers_dict.items()}
server = hdr.get("server", "")
powered_by = hdr.get("x-powered-by", "")
csp = hdr.get("content-security-policy", "")
x_frame = hdr.get("x-frame-options", "")
hsts = hdr.get("strict-transport-security", "")
x_content_type = hdr.get("x-content-type-options", "")
set_cookie = hdr.get("set-cookie", "")
cors = hdr.get("access-control-allow-origin", "")

if server:
    tech_tags.add(f"server:{server.split('/')[0].lower().strip()}")
if powered_by:
    tech_tags.add(f"powered-by:{powered_by.lower().split('/')[0].strip()}")

if not csp:
    security_issues.append("Missing Content-Security-Policy header")
if not x_frame:
    security_issues.append("Missing X-Frame-Options header (clickjacking risk)")
if not hsts and parsed_url.scheme == "https":
    security_issues.append("Missing Strict-Transport-Security header")
if not x_content_type:
    security_issues.append("Missing X-Content-Type-Options header")
if cors == "*":
    security_issues.append("Overly permissive CORS policy (Access-Control-Allow-Origin: *)")
if set_cookie and "httponly" not in set_cookie.lower():
    security_issues.append("Session cookie missing HttpOnly flag")
if set_cookie and parsed_url.scheme == "https" and "secure" not in set_cookie.lower():
    security_issues.append("Session cookie missing Secure flag")

services.append({
    "port": port,
    "protocol": "tcp",
    "name": parsed_url.scheme,
    "product": server or None,
    "version": None,
})
tags = list({"observed", "tool:http_metadata"} | tech_tags)

asset_rec = {
    "type": "asset",
    "asset_id": asset_id,
    "kind": "web_application",
    "hostname": hostname,
    "base_url": base_url,
    "services": services,
    "tags": tags,
    "metadata": {
        "source": "http_metadata_probe",
        "http_status": http_status,
        "server": server,
        "powered_by": powered_by,
        "has_csp": bool(csp),
        "has_hsts": bool(hsts),
        "has_x_frame_options": bool(x_frame),
    },
}
if ip_address:
    asset_rec["ip_address"] = ip_address

severity = "medium" if security_issues else "info"
description = f"HTTP metadata probe for {base_url}"
if http_status:
    description += f" returned HTTP {http_status}"
description += ". "
if security_issues:
    description += f"{len(security_issues)} security header issue(s): " + "; ".join(security_issues) + "."
else:
    description += "No security header issues detected."

finding_title = "Web surface metadata collected"
if security_issues:
    finding_title += f" — {len(security_issues)} header issue(s)"

records.append({
    "type": "summary",
    "text": f"HTTP metadata probe for {base_url}: HTTP {http_status}, {len(security_issues)} header issue(s).",
})
records.append(asset_rec)
records.append({
    "type": "finding",
    "finding_id": f"finding-{asset_id}-http-metadata",
    "title": finding_title,
    "severity": severity,
    "description": description,
    "asset_refs": [asset_id],
    "evidence_refs": [base_url],
    "metadata": {
        "source": "http_metadata_probe",
        "security_issues": security_issues,
        "observed_headers": {
            k: v for k, v in hdr.items()
            if k in {
                # Security headers
                "server", "x-powered-by", "content-security-policy",
                "x-frame-options", "strict-transport-security",
                "x-content-type-options", "access-control-allow-origin",
                # Critical for exploit writers — what cookie name does
                # the server actually set?  What auth scheme is in use?
                # What does redirect/Content-Type say about the framework?
                "set-cookie", "content-type", "content-length",
                "location", "www-authenticate", "x-aspnet-version",
                "x-csrf-token", "x-request-id",
            }
        },
    },
})
for note in notes_list:
    records.append({"type": "note", "text": note})
for issue in security_issues:
    records.append({"type": "note", "text": f"Security header issue: {issue}"})

records.append({
    "type": "output_context",
    "observed_base_url": base_url,
    "http_status": http_status,
    "ip_address": ip_address,
    "server": server,
    "powered_by": powered_by,
    "security_issues": security_issues,
    "open_ports": [port],
    # Surface the actual response headers — set-cookie / location / etc —
    # into output_context so downstream workers can read them through
    # ``state.evidence`` and write an exploit that talks to the server
    # the way it ACTUALLY behaves (correct cookie name, redirect target,
    # framework hint), not the way the writeup says it should behave.
    "response_headers": {k: v for k, v in hdr.items()},
    "set_cookie": set_cookie,
    "manual_checks": [
        f"Review all HTTP response headers for {base_url}",
        f"Inspect authentication and session handling at {base_url}",
        "Test all user-supplied input fields for injection vulnerabilities",
        "Verify TLS/SSL configuration" if parsed_url.scheme == "https" else "Enforce HTTPS and set HSTS",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "asset_id": request.metadata.get("asset_id"),
        "base_url": request.metadata.get("base_url"),
        "hostname": request.metadata.get("hostname"),
        "timeout_s": request.timeout_s,
    }
    if not payload["base_url"]:
        raise ToolExecutionError("local_http_metadata requires metadata.base_url")
    return ["-c", SCRIPT, json.dumps(payload)]

def build_tool_output(request, result, parsed):
    from killchain_docker.tools.output_builder import base_output, extract_endpoints, extract_vulnerabilities
    ctx = parsed.output_context or {}
    source = request.capability or request.tool_name
    asset_ref = request.metadata.get("asset_id")
    output = base_output(request, result, parsed)
    output.endpoints = extract_endpoints(ctx, request, source=source, asset_ref=asset_ref)
    output.vulnerabilities = extract_vulnerabilities(ctx, source=source, tool_name=request.tool_name, asset_ref=asset_ref)
    return output
