"""Source code review tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import (
    SHARED_FILE_TARGETS_SNIPPET,
    SHARED_FLAG_DETECTION_SNIPPET,
)


TOOL_NAME = "source_review"

_SCRIPT_HEADER = r"""
import json
import re
import sys
from pathlib import Path

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

"""

_SCRIPT_BODY = r"""
if not source_files:
    records.append({"type": "summary", "text": "Source review failed: missing required metadata.source_files."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_sources": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)


targets = _resolve_file_targets(files_root, source_files, max_files=max_files, kind="source")
for target in targets:
    relpath = target["display"]
    path = Path(target["path"])
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    inspected.append(relpath)

    for route in route_re.findall(content):
        if route not in route_hits and any(token in route.lower() for token in ("admin", "login", "upload", "debug", "api", "flag")):
            route_hits.append(route)

    lowered = content.lower()
    if any(token in lowered for token in ("password", "secret", "token", "api_key", "apikey", "bearer ", "authorization")):
        secret_hits.append(relpath)

    for flag in flag_re.findall(content):
        if flag not in flag_candidates and _plausible_flag(flag):
            flag_candidates.append(flag)

if not inspected:
    records.append({"type": "summary", "text": "Source review failed: no requested source files could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "source_files": source_files[:max_files], "inspected_sources": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

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

SCRIPT = _SCRIPT_HEADER + SHARED_FLAG_DETECTION_SNIPPET + SHARED_FILE_TARGETS_SNIPPET + _SCRIPT_BODY


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "source_files": request.metadata.get("source_files", []),
        "max_files": request.metadata.get("max_files", 12),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
