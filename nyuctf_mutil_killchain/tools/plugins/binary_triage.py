"""Binary artifact strings triage tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "binary_triage"

SCRIPT = r"""
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
binary_files = payload.get("binary_files") or []
max_files = int(payload.get("max_files", 6))

records = []
notes_list = []
flag_candidates = []
interesting_strings = {}
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")

for relpath in binary_files[:max_files]:
    path = files_root / relpath
    if not path.is_file():
        continue
    inspected.append(relpath)
    try:
        file_type = subprocess.run(
            ["file", "-b", str(path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout.strip()
    except Exception:
        file_type = ""

    try:
        strings_output = subprocess.run(
            ["strings", "-n", "6", str(path)],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        ).stdout[:12000]
    except Exception:
        strings_output = ""

    hits = []
    for line in strings_output.splitlines():
        lowered = line.lower()
        if any(token in lowered for token in ("flag", "password", "secret", "token", "api", "key", "http://", "https://", "/bin/sh")):
            hits.append(line[:160])
    if hits:
        interesting_strings[relpath] = hits[:12]

    for flag in flag_re.findall(strings_output):
        if flag not in flag_candidates:
            flag_candidates.append(flag)

    records.append({
        "type": "note",
        "text": f"Binary {relpath}: {file_type or 'unknown type'}",
    })

records.append({
    "type": "summary",
    "text": (
        f"Binary triage completed for {len(inspected)} file(s): "
        f"{len(flag_candidates)} flag candidate(s), {sum(len(v) for v in interesting_strings.values())} interesting string hit(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-binary-triage",
    "title": "Binary artifacts reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} bundled binary artifact(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "binary_triage", "inspected": inspected},
})

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-binary-flags",
        "title": "Flag-like token recovered from binary strings",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from bundled binaries.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "binary_triage", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_binaries": inspected,
    "interesting_strings": interesting_strings,
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Review interesting strings for hardcoded credentials or command paths.",
        "Validate any recovered flag-like token before submission.",
        "Escalate to reversing/debugging workflow if binaries still appear central to the challenge.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "binary_files": request.metadata.get("binary_files", []),
        "max_files": request.metadata.get("max_files", 6),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
