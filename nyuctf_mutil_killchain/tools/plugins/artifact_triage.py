"""Top-level artifact triage tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "artifact_triage"

SCRIPT = r"""
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
challenge_files = payload.get("challenge_files") or []
max_files = int(payload.get("max_files", 80))

records = []
notes_list = []
interesting_files = []
flag_candidates = []
web_sources = []
binaries = []
archives = []
database_files = []
pcap_files = []
repo_paths = set()
text_files = []
source_suffixes = {
    ".c", ".cc", ".cpp", ".cxx", ".cs", ".go", ".h", ".hpp", ".htm", ".html",
    ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql",
    ".sv", ".swift", ".tera", ".ts", ".tsx", ".v",
}
text_suffixes = {
    ".cfg", ".csv", ".htm", ".html", ".ini", ".json", ".md", ".txt", ".xml",
    ".yaml", ".yml", ".toml",
}

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")

if not files_root.exists():
    records.append({"type": "summary", "text": f"Artifact triage skipped: {files_root} does not exist."})
    records.append({"type": "note", "text": f"Challenge files root not found: {files_root}"})
else:
    files = sorted(path for path in files_root.rglob("*") if path.is_file())[:max_files]
    for path in files:
        relpath = str(path.relative_to(files_root))
        suffix = path.suffix.lower()
        size = path.stat().st_size
        file_type = ""
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

        lowered_type = file_type.lower()
        if "elf" in lowered_type or "pe32" in lowered_type or suffix in {".bin", ".so", ".exe"}:
            binaries.append(relpath)
        elif suffix in {".zip", ".tar", ".tgz", ".gz", ".7z", ".rar"}:
            archives.append(relpath)
        elif suffix in {".db", ".sqlite", ".sqlite3"}:
            database_files.append(relpath)
        elif suffix in {".pcap", ".pcapng", ".cap"}:
            pcap_files.append(relpath)
        elif suffix in source_suffixes:
            web_sources.append(relpath)
        elif "text" in lowered_type or suffix in text_suffixes:
            text_files.append(relpath)

        rel_parts = Path(relpath).parts
        if ".git" in rel_parts:
            git_index = rel_parts.index(".git")
            repo_root = Path(*rel_parts[:git_index]) if git_index > 0 else Path(".")
            repo_paths.add(str(repo_root))
        elif (path.parent / ".git").exists():
            repo_root = path.parent.relative_to(files_root)
            repo_paths.add(str(repo_root))

        sample = ""
        try:
            if size <= 2_000_000 and ("text" in lowered_type or suffix in text_suffixes or suffix in source_suffixes):
                sample = path.read_text(encoding="utf-8", errors="ignore")[:4000]
            elif size <= 5_000_000 and relpath in binaries[:5]:
                sample = subprocess.run(
                    ["strings", "-n", "6", str(path)],
                    capture_output=True,
                    text=True,
                    timeout=8,
                    check=False,
                ).stdout[:4000]
        except Exception:
            sample = ""

        if sample:
            found_flags = flag_re.findall(sample)
            for flag in found_flags:
                if flag not in flag_candidates:
                    flag_candidates.append(flag)

            lowered_sample = sample.lower()
            if any(token in lowered_sample for token in ("flag", "password", "secret", "token", "api_key", "todo")):
                interesting_files.append({
                    "path": relpath,
                    "size": size,
                    "type": file_type,
                })

    records.append({
        "type": "summary",
        "text": (
            f"Artifact triage completed for {files_root}: {len(files)} file(s), "
            f"{len(binaries)} binary artifact(s), {len(web_sources)} source/web artifact(s), "
            f"{len(flag_candidates)} flag candidate(s), {len(database_files)} database file(s), "
            f"{len(pcap_files)} pcap file(s), {len(repo_paths)} repo path(s)."
        ),
    })

    records.append({
        "type": "finding",
        "finding_id": "finding-challenge-files-inventory",
        "title": "Challenge files inventoried",
        "severity": "info",
        "description": f"Inventory completed over {len(files)} file(s) under {files_root}.",
        "asset_refs": ["challenge-files"],
        "metadata": {
            "source": "artifact_triage",
            "challenge_files": challenge_files,
            "binary_count": len(binaries),
            "archive_count": len(archives),
            "database_count": len(database_files),
            "pcap_count": len(pcap_files),
            "text_count": len(text_files),
            "repo_count": len(repo_paths),
        },
    })

    if web_sources:
        records.append({
            "type": "finding",
            "finding_id": "finding-challenge-files-web-sources",
            "title": "Web/source artifacts bundled with challenge",
            "severity": "medium",
            "description": f"Found {len(web_sources)} source or web-facing artifact(s) in the bundled files.",
            "asset_refs": ["challenge-files"],
            "evidence_refs": web_sources[:5],
            "metadata": {"source": "artifact_triage", "web_sources": web_sources[:20]},
        })

    if flag_candidates:
        records.append({
            "type": "finding",
            "finding_id": "finding-challenge-files-flag-candidates",
            "title": "Flag-like token found in challenge files",
            "severity": "high",
            "description": f"Recovered {len(flag_candidates)} flag candidate(s) from challenge files.",
            "asset_refs": ["challenge-files"],
            "evidence_refs": flag_candidates[:5],
            "metadata": {"source": "artifact_triage", "flag_candidates": flag_candidates[:10]},
        })

    if interesting_files:
        records.append({"type": "note", "text": f"Interesting files: {interesting_files[:10]}"})
    if archives:
        records.append({"type": "note", "text": f"Archive files discovered: {archives[:10]}"})
    if binaries:
        records.append({"type": "note", "text": f"Binary files discovered: {binaries[:10]}"})
    if database_files:
        records.append({"type": "note", "text": f"Database files discovered: {database_files[:10]}"})
    if pcap_files:
        records.append({"type": "note", "text": f"PCAP files discovered: {pcap_files[:10]}"})
    if repo_paths:
        records.append({"type": "note", "text": f"Repository paths discovered: {sorted(repo_paths)[:10]}"})

    records.append({
        "type": "output_context",
        "files_root": str(files_root),
        "challenge_files": challenge_files,
        "binary_files": binaries[:20],
        "archive_files": archives[:20],
        "database_files": database_files[:20],
        "pcap_files": pcap_files[:20],
        "repo_paths": sorted(repo_paths)[:20],
        "web_source_files": web_sources[:20],
        "text_files": text_files[:20],
        "interesting_files": interesting_files[:20],
        "flag_candidates": flag_candidates[:10],
        "manual_checks": [
            "Inspect bundled binaries and scripts for hardcoded secrets.",
            "Extract archives and review source files for hidden routes or credentials.",
            "Validate any recovered flag-like token before submission.",
        ],
    })

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "challenge_files": request.metadata.get("challenge_files", []),
        "max_files": request.metadata.get("max_files", 80),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
