"""TCP service banner collection tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionError, ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FLAG_DETECTION_SNIPPET


TOOL_NAME = "tcp_banner_probe"

_SCRIPT_HEADER = r"""
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
"""

_SCRIPT_BODY = r"""

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

SCRIPT = _SCRIPT_HEADER + SHARED_FLAG_DETECTION_SNIPPET + _SCRIPT_BODY


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

def build_tool_output(request, result, parsed):
    from killchain_docker.tools.output_builder import base_output, extract_flag_candidates
    ctx = parsed.output_context or {}
    source = request.capability or request.tool_name
    output = base_output(request, result, parsed)
    output.flag_candidates = extract_flag_candidates(ctx, source=source, flag_format=request.metadata.get("flag_format"))
    return output
