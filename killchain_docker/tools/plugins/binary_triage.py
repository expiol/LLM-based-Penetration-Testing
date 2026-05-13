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

    # Two passes: explicit "interesting" tokens (credentials / endpoints /
    # crypto-algorithm hints / error messages that betray the algorithm) AND
    # a generic short-string fallback that ships the binary's distinctive
    # printable strings to the solver even when none of the keyword tokens
    # match.  This is critical for non-trivial CTF binaries where the giveaway
    # is something like ``Supplied tap values out of range`` (a stock LFSR
    # error message): without the fallback, ``interesting_strings`` would be
    # ``{}`` and the LLM solver would never see the cipher-identifying string
    # in the structured evidence.
    keyword_hits: list[str] = []
    fallback_hits: list[str] = []
    interesting_tokens = (
        # Credentials / secrets:
        "flag", "password", "secret", "token", "api", "key", "auth", "creds",
        # Reachable endpoints:
        "http://", "https://", "/bin/sh", "ftp://",
        # Crypto algorithm names:
        "aes", "des", "rsa", "rc4", "rc5", "blowfish", "twofish", "chacha",
        "salsa", "sha256", "sha512", "md5", "hmac",
        # Stream-cipher / RNG hints (tap/lfsr is a common giveaway for LFSR
        # ciphers; rand/srand/prng for time-seeded rand keystreams):
        "lfsr", "tap", "shift register", "xor", "cipher", "crypt",
        "rand", "srand", "prng", "seed", "iv ", "nonce", "stream",
        # Encoding hints:
        "base64", "base32", "rot13", "hexdump",
        # File-format magic numbers / tags often serve as keystone clues:
        "magic", "header", "stfu", "ctf{",
        # Error messages — frequently betray the algorithm choice:
        "out of range", "invalid key", "could not encode", "could not decode",
        "wrong size", "padding", "block size", "supplied",
    )
    for line in strings_output.splitlines():
        cleaned = line.strip()
        if not cleaned:
            continue
        lowered = cleaned.lower()
        if any(token in lowered for token in interesting_tokens):
            keyword_hits.append(cleaned[:200])
            continue
        # Fallback: capture distinctive printable strings (alphanumeric
        # presence + at least 6 chars + at most ~80 chars).  Filters out
        # ELF section headers (``.shstrtab``, ``.dynsym``, ``GLIBC_2.x``)
        # and trivial padding so the bucket isn't drowned in noise.
        if 6 <= len(cleaned) <= 80 and any(c.isalpha() for c in cleaned):
            if cleaned.startswith(".") or cleaned.startswith("__"):
                continue
            if cleaned.startswith("GLIBC_") or cleaned in ("libc.so.6", "/lib/ld-linux.so.2"):
                continue
            fallback_hits.append(cleaned[:200])

    selected = keyword_hits[:12]
    # Top up to 18 total with deduplicated fallback hits so the solver always
    # gets at least a sample of the binary's printable strings, but never
    # more than ~18 lines per binary (controls prompt size).
    seen = set(selected)
    for cand in fallback_hits:
        if len(selected) >= 18:
            break
        if cand in seen:
            continue
        selected.append(cand)
        seen.add(cand)
    if selected:
        interesting_strings[relpath] = selected

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
