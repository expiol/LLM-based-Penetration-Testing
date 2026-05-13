"""CTF-wide flag harvesting tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FLAG_DETECTION_SNIPPET


TOOL_NAME = "flag_harvest"

_SCRIPT_HEADER = r"""
import base64
import binascii
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
seed_terms = [str(item).lower() for item in (payload.get("seed_terms") or []) if str(item).strip()]
max_files = int(payload.get("max_files", 120))

records = []
notes_list = []
flag_candidates = []
blob_candidates = []
decoded_candidates = []
interesting_paths = []
evidence_snippets = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
blob_re = re.compile(r"\b(?:[A-Fa-f0-9]{16,}|[A-Za-z0-9+/]{20,}={0,2})\b")
path_re = re.compile(r"(/(?:[A-Za-z0-9_.-]+/?){1,6})")

"""

_SCRIPT_BODY = r"""

text_suffixes = {
    ".cfg", ".conf", ".csv", ".env", ".go", ".htm", ".html", ".ini", ".java", ".js", ".json",
    ".md", ".php", ".py", ".rb", ".rs", ".sh", ".sql", ".tera", ".toml", ".txt", ".xml", ".yaml", ".yml",
}


def add_flag(candidate):
    if candidate and candidate not in flag_candidates and _plausible_flag(candidate):
        flag_candidates.append(candidate)


def add_path(candidate):
    lowered = candidate.lower()
    if any(token in lowered for token in ("admin", "api", "auth", "backup", "debug", "flag", "login", "upload")):
        if candidate not in interesting_paths:
            interesting_paths.append(candidate)


def try_decode(token):
    if token in blob_candidates:
        return
    blob_candidates.append(token)
    decoded_text = None
    if re.fullmatch(r"[A-Fa-f0-9]{16,}", token) and len(token) % 2 == 0:
        try:
            decoded_text = bytes.fromhex(token).decode("utf-8", errors="ignore")
        except Exception:
            decoded_text = None
    elif len(token) % 4 == 0:
        try:
            decoded_text = base64.b64decode(token).decode("utf-8", errors="ignore")
        except (binascii.Error, ValueError):
            decoded_text = None
    if not decoded_text:
        return
    decoded_text = decoded_text.strip()
    if not decoded_text:
        return
    if decoded_text not in decoded_candidates:
        decoded_candidates.append(decoded_text[:400])
    for candidate in flag_re.findall(decoded_text):
        add_flag(candidate)
    for path in path_re.findall(decoded_text):
        add_path(path)


if not files_root.exists():
    records.append({"type": "summary", "text": f"Flag harvesting skipped: {files_root} does not exist."})
else:
    files = sorted(path for path in files_root.rglob("*") if path.is_file())[:max_files]
    for path in files:
        relpath = str(path.relative_to(files_root))
        suffix = path.suffix.lower()
        text = ""
        try:
            if suffix in text_suffixes or path.stat().st_size <= 1_000_000:
                text = path.read_text(encoding="utf-8", errors="ignore")[:16000]
        except Exception:
            text = ""
        if not text and path.stat().st_size <= 3_000_000:
            try:
                text = subprocess.run(
                    ["strings", "-n", "6", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                ).stdout[:16000]
            except Exception:
                text = ""
        if not text:
            continue

        lowered = text.lower()
        if seed_terms and not any(term in lowered for term in seed_terms):
            if not any(token in lowered for token in ("flag", "ctf", "token", "secret", "submit")):
                continue

        matches = flag_re.findall(text)
        for match in matches:
            add_flag(match)
        for path_match in path_re.findall(text):
            add_path(path_match)
        for blob in blob_re.findall(text):
            try_decode(blob)

        if matches or any(token in lowered for token in ("flag", "submit", "secret", "ctf")):
            snippet = text[:240].replace("\n", " ").strip()
            if snippet and snippet not in evidence_snippets:
                evidence_snippets.append(f"{relpath}: {snippet}")

    records.append({
        "type": "summary",
        "text": (
            f"Flag harvesting reviewed {len(files) if 'files' in locals() else 0} file(s) under {files_root}, "
            f"recovered {len(flag_candidates)} flag candidate(s), and decoded {len(decoded_candidates)} candidate blob(s)."
        ),
    })

    if flag_candidates:
        records.append({
            "type": "finding",
            "finding_id": "finding-flag-harvest-candidates",
            "title": "Flag candidates recovered across challenge artifacts",
            "severity": "high",
            "description": f"Recovered {len(flag_candidates)} grounded flag candidate(s) during a cross-artifact search.",
            "asset_refs": ["challenge-files"],
            "evidence_refs": flag_candidates[:8],
            "metadata": {
                "source": "flag_harvest",
                "decoded_candidates": decoded_candidates[:8],
                "interesting_paths": interesting_paths[:12],
            },
        })

    for note in notes_list:
        records.append({"type": "note", "text": note})

    records.append({
        "type": "output_context",
        "files_root": str(files_root),
        "flag_candidates": flag_candidates[:16],
        "blob_candidates": blob_candidates[:20],
        "decoded_candidates": decoded_candidates[:12],
        "interesting_paths": interesting_paths[:20],
        "evidence_snippets": evidence_snippets[:12],
        "manual_checks": [
            "Prioritize candidates that match the challenge flag format or appear near submit/flag logic.",
            "Inspect decoded blobs and nearby routes for additional pivots.",
            "Validate all recovered flag candidates before submission.",
        ],
    })

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""

SCRIPT = _SCRIPT_HEADER + SHARED_FLAG_DETECTION_SNIPPET + _SCRIPT_BODY


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "seed_terms": request.metadata.get("seed_terms", []),
        "max_files": request.metadata.get("max_files", 120),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
