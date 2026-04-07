"""CTF credential harvesting tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "credential_harvest"

SCRIPT = r"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
seed_terms = [str(item).lower() for item in (payload.get("seed_terms") or []) if str(item).strip()]
max_files = int(payload.get("max_files", 80))

records = []
notes_list = []
credential_candidates = []
credential_ids = []
flag_candidates = []
interesting_paths = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
path_re = re.compile(r"(/(?:[A-Za-z0-9_.-]+/?){1,6})")
assign_re = re.compile(
    r"(?i)\b(?P<key>username|user|login|email|password|passwd|pwd|secret|token|api[_-]?key|apikey|bearer|cookie|session)\b"
    r"\s*[:=]\s*['\"]?(?P<value>[^\s'\";]{3,200})"
)

text_suffixes = {
    ".cfg", ".conf", ".csv", ".env", ".htm", ".html", ".ini", ".js", ".json", ".md", ".php",
    ".py", ".rb", ".sh", ".sql", ".txt", ".xml", ".yaml", ".yml", ".toml",
}


def add_flag_candidates(text):
    for candidate in flag_re.findall(text or ""):
        if candidate not in flag_candidates:
            flag_candidates.append(candidate)


def add_paths(text):
    for match in path_re.findall(text or ""):
        lowered = match.lower()
        if any(token in lowered for token in ("admin", "api", "auth", "backup", "debug", "flag", "login", "upload")):
            if match not in interesting_paths:
                interesting_paths.append(match)


def add_candidate(path_text, key, value, username_hint):
    normalized_key = key.lower()
    credential_type = "token"
    if any(token in normalized_key for token in ("password", "passwd", "pwd", "secret")):
        credential_type = "password"
    elif "cookie" in normalized_key or "session" in normalized_key:
        credential_type = "cookie"
    username = username_hint or normalized_key
    secret_preview = value if len(value) <= 8 else value[:4] + "..." + value[-4:]
    fingerprint = hashlib.sha1(f"{path_text}:{normalized_key}:{username}:{value}".encode("utf-8")).hexdigest()[:12]
    credential_id = f"credential-{fingerprint}"
    if credential_id in credential_ids:
        return
    credential_ids.append(credential_id)
    candidate = {
        "credential_id": credential_id,
        "username": username,
        "secret_value": value,
        "credential_type": credential_type,
        "path": path_text,
        "key": key,
        "asset_ref": "challenge-files",
        "source": "credential_harvest",
        "secret_preview": secret_preview,
    }
    credential_candidates.append(candidate)
    records.append({
        "type": "credential",
        "credential_id": credential_id,
        "username": username,
        "secret_ref": f"file:{path_text}:{key}",
        "credential_type": credential_type,
        "asset_ref": "challenge-files",
        "source": "credential_harvest",
        "metadata": {
            "path": path_text,
            "key": key,
            "secret_preview": secret_preview,
            "secret_value": value,
        },
    })


if not files_root.exists():
    records.append({"type": "summary", "text": f"Credential harvesting skipped: {files_root} does not exist."})
else:
    files = sorted(path for path in files_root.rglob("*") if path.is_file())[:max_files]
    for path in files:
        relpath = str(path.relative_to(files_root))
        suffix = path.suffix.lower()
        text = ""
        try:
            if suffix in text_suffixes or path.stat().st_size <= 1_000_000:
                text = path.read_text(encoding="utf-8", errors="ignore")[:12000]
        except Exception:
            text = ""
        if not text and path.stat().st_size <= 2_000_000:
            try:
                text = subprocess.run(
                    ["strings", "-n", "6", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                ).stdout[:12000]
            except Exception:
                text = ""

        if not text:
            continue

        lowered = text.lower()
        if seed_terms and not any(term in lowered for term in seed_terms):
            if not any(token in lowered for token in ("user", "pass", "token", "secret", "bearer", "cookie", "login")):
                continue

        add_flag_candidates(text)
        add_paths(text)

        username_hints = []
        for match in assign_re.finditer(text):
            key = match.group("key")
            value = match.group("value")
            lowered_key = key.lower()
            if any(token in lowered_key for token in ("username", "user", "login", "email")):
                if value not in username_hints:
                    username_hints.append(value)

        for match in assign_re.finditer(text):
            key = match.group("key")
            value = match.group("value")
            lowered_key = key.lower()
            if any(token in lowered_key for token in ("username", "user", "login", "email")):
                continue
            username_hint = username_hints[0] if username_hints else None
            add_candidate(relpath, key, value, username_hint)
            if len(credential_candidates) >= 16:
                break

        if len(credential_candidates) >= 16:
            notes_list.append("Credential harvesting truncated after 16 candidate credentials.")
            break

    records.append({
        "type": "summary",
        "text": (
            f"Credential harvesting reviewed {len(files) if 'files' in locals() else 0} file(s) under {files_root} "
            f"and recovered {len(credential_candidates)} credential candidate(s)."
        ),
    })

    if credential_candidates:
        records.append({
            "type": "finding",
            "finding_id": "finding-credential-harvest-candidates",
            "title": "Credential-like material recovered from challenge artifacts",
            "severity": "high",
            "description": f"Recovered {len(credential_candidates)} credential candidate(s) from bundled challenge files.",
            "asset_refs": ["challenge-files"],
            "evidence_refs": [candidate["path"] for candidate in credential_candidates[:5]],
            "metadata": {
                "source": "credential_harvest",
                "credential_ids": credential_ids[:12],
                "credential_types": [candidate["credential_type"] for candidate in credential_candidates[:12]],
            },
        })

    for note in notes_list:
        records.append({"type": "note", "text": note})

    records.append({
        "type": "output_context",
        "files_root": str(files_root),
        "credential_candidates": credential_candidates[:16],
        "credential_ids": credential_ids[:16],
        "flag_candidates": flag_candidates[:10],
        "interesting_paths": interesting_paths[:20],
        "manual_checks": [
            "Prioritize credential candidates that align with exposed services or login paths.",
            "Check whether cookies, bearer tokens, or default passwords map to reachable challenge endpoints.",
            "Validate any recovered flag-like tokens before submission.",
        ],
    })

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "seed_terms": request.metadata.get("seed_terms", []),
        "max_files": request.metadata.get("max_files", 80),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
