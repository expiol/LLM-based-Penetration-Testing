"""Packet capture review tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "pcap_review"

SCRIPT = r"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
pcap_files = payload.get("pcap_files") or []
max_files = int(payload.get("max_files", 6))

records = []
flag_candidates = []
interesting_urls = []
interesting_hosts = []
credential_hits = []
protocol_notes = []
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
url_re = re.compile(r"https?://[A-Za-z0-9._:/?&=%#@+-]{6,200}")
host_re = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,20}\b")
tshark_bin = shutil.which("tshark")

for relpath in pcap_files[:max_files]:
    path = files_root / relpath
    if not path.is_file():
        continue
    inspected.append(relpath)

    if tshark_bin:
        try:
            result = subprocess.run(
                [tshark_bin, "-r", str(path), "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if result.stdout.strip():
                protocol_notes.append(f"{relpath}: {result.stdout.splitlines()[-1][:180]}")
        except Exception as exc:
            records.append({"type": "note", "text": f"tshark summary failed for {relpath}: {type(exc).__name__}: {exc}"})

    try:
        strings_output = subprocess.run(
            ["strings", "-n", "6", str(path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        ).stdout[:20000]
    except Exception as exc:
        records.append({"type": "note", "text": f"strings failed for {relpath}: {type(exc).__name__}: {exc}"})
        continue

    for url in url_re.findall(strings_output):
        if url not in interesting_urls:
            interesting_urls.append(url)
    for host in host_re.findall(strings_output):
        lowered = host.lower()
        if "." in host and lowered not in {"localhost.localdomain"} and host not in interesting_hosts:
            interesting_hosts.append(host)
    for flag in flag_re.findall(strings_output):
        if flag not in flag_candidates:
            flag_candidates.append(flag)

    for line in strings_output.splitlines():
        lowered = line.lower()
        if any(token in lowered for token in ("authorization:", "bearer ", "cookie:", "password=", "passwd=", "token=", "apikey", "api_key")):
            credential_hits.append(f"{relpath}:{line[:180]}")

records.append({
    "type": "summary",
    "text": (
        f"PCAP review completed for {len(inspected)} file(s): "
        f"{len(interesting_urls)} URL(s), {len(credential_hits)} credential hit(s), "
        f"{len(flag_candidates)} flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-pcap-review",
    "title": "Packet capture artifacts reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} packet capture artifact(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "pcap_review", "protocol_notes": protocol_notes[:10]},
})

if interesting_urls or interesting_hosts:
    records.append({
        "type": "finding",
        "finding_id": "finding-pcap-network-observations",
        "title": "Interesting hosts or URLs recovered from packet captures",
        "severity": "medium",
        "description": f"Recovered {len(interesting_hosts)} host(s) and {len(interesting_urls)} URL(s) from packet capture content.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": (interesting_urls + interesting_hosts)[:8],
        "metadata": {"source": "pcap_review", "hosts": interesting_hosts[:20], "urls": interesting_urls[:20]},
    })

if credential_hits:
    records.append({
        "type": "finding",
        "finding_id": "finding-pcap-credentials",
        "title": "Credential-like material found in packet capture content",
        "severity": "high",
        "description": f"Detected {len(credential_hits)} credential-like hit(s) in packet capture content.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": credential_hits[:8],
        "metadata": {"source": "pcap_review", "credential_hits": credential_hits[:20]},
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-pcap-flags",
        "title": "Flag-like token found in packet capture content",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from packet capture content.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "pcap_review", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_pcaps": inspected,
    "hosts": interesting_hosts[:20],
    "urls": interesting_urls[:20],
    "credential_hits": credential_hits[:20],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Inspect recovered URLs, cookies, and authorization headers for challenge pivots.",
        "Review packet captures in Wireshark when strings output is insufficient.",
        "Validate any recovered flag-like token before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "pcap_files": request.metadata.get("pcap_files", []),
        "max_files": request.metadata.get("max_files", 6),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
