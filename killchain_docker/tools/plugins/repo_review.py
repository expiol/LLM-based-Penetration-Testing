"""Embedded git repository review tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest

TOOL_NAME = "repo_review"

SCRIPT = r"""
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files").resolve()
repo_paths = payload.get("repo_paths") or []
max_files = int(payload.get("max_files", 4))

records = []
flag_candidates = []
commit_summaries = {}
grep_hits = []
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
grep_pattern = r"flag\{|secret|token|password|api[_-]?key|apikey"

if not repo_paths:
    records.append({"type": "summary", "text": "Repository review failed: missing required metadata.repo_paths."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_repos": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

def _safe_repo_targets(values):
    out = []
    for raw in values:
        if len(out) >= max_files:
            break
        text = str(raw).strip()
        if not text:
            continue
        if text.startswith(str(files_root) + "/"):
            text = text[len(str(files_root)) + 1 :]
        path = Path(text)
        if path.is_absolute():
            candidate = path.resolve()
            try:
                candidate.relative_to(files_root)
            except ValueError:
                continue
            if candidate.exists():
                out.append(candidate)
            continue
        if ".." in Path(text).parts:
            continue
        if any(ch in text for ch in "*?["):
            for candidate in sorted(files_root.glob(text)):
                if len(out) >= max_files:
                    break
                if candidate.exists():
                    out.append(candidate.resolve())
        else:
            candidate = (files_root / text).resolve()
            try:
                candidate.relative_to(files_root)
            except ValueError:
                continue
            if candidate.exists():
                out.append(candidate)
    return out

for repo_path in _safe_repo_targets(repo_paths):
    if not repo_path.exists():
        continue
    repo_rel = str(repo_path.relative_to(files_root))
    if not (repo_path / ".git").exists():
        continue
    inspected.append(str(repo_path.relative_to(files_root)))

    try:
        log_result = subprocess.run(
            ["git", "-C", str(repo_path), "log", "--oneline", "-n", "12"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        log_lines = [line.strip() for line in log_result.stdout.splitlines() if line.strip()]
        commit_summaries[str(repo_path.relative_to(files_root))] = log_lines[:12]
    except Exception as exc:
        records.append({"type": "note", "text": f"git log failed for {repo_rel}: {type(exc).__name__}: {exc}"})

    try:
        grep_result = subprocess.run(
            ["git", "-C", str(repo_path), "grep", "-n", "-I", "-E", grep_pattern, "HEAD", "--"],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        for line in grep_result.stdout.splitlines()[:40]:
            if line not in grep_hits:
                grep_hits.append(line[:220])
            for flag in flag_re.findall(line):
                if flag not in flag_candidates:
                    flag_candidates.append(flag)
    except Exception as exc:
        records.append({"type": "note", "text": f"git grep failed for {repo_rel}: {type(exc).__name__}: {exc}"})

if not inspected:
    records.append({"type": "summary", "text": "Repository review failed: no requested repo paths could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "repo_paths": repo_paths[:max_files], "inspected_repos": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

records.append({
    "type": "summary",
    "text": (
        f"Repository review completed for {len(inspected)} repo(s): "
        f"{sum(len(v) for v in commit_summaries.values())} commit summary line(s), "
        f"{len(grep_hits)} grep hit(s), {len(flag_candidates)} flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-repo-review",
    "title": "Embedded repositories reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} embedded git repository path(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "repo_review", "commit_summaries": commit_summaries},
})

if grep_hits:
    records.append({
        "type": "finding",
        "finding_id": "finding-repo-grep-hits",
        "title": "Interesting git history or tracked content found",
        "severity": "medium",
        "description": f"Detected {len(grep_hits)} interesting git grep hit(s) in embedded repositories.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": grep_hits[:8],
        "metadata": {"source": "repo_review", "grep_hits": grep_hits[:20]},
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-repo-flags",
        "title": "Flag-like token found in repository content",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from embedded repository content.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "repo_review", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_repos": inspected,
    "commit_summaries": commit_summaries,
    "grep_hits": grep_hits[:20],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Inspect commit history for reverted flags, secrets, or backup routes.",
        "Search previous revisions if the flag may have been removed from the current tree.",
        "Validate any recovered flag-like token before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "repo_paths": request.metadata.get("repo_paths", []),
        "max_files": request.metadata.get("max_files", 4),
    }
    return ["-c", SCRIPT, json.dumps(payload)]

def build_tool_output(request, result, parsed):
    from killchain_docker.tools.output_builder import base_output, extract_flag_candidates, extract_artifacts
    ctx = parsed.output_context or {}
    source = request.capability or request.tool_name
    output = base_output(request, result, parsed)
    output.flag_candidates = extract_flag_candidates(ctx, source=source, flag_format=request.metadata.get("flag_format"))
    output.artifacts = extract_artifacts(ctx, source=source, keys={"inspected_repos": "repository"})
    return output
