"""Runtime execution probe for bundled script artifacts."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "runtime_probe"

SCRIPT = r"""
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
source_files = payload.get("source_files") or []
max_files = int(payload.get("max_files", 8))
flag_format = str(payload.get("flag_format") or "")

records = []
notes_list = []
executed_scripts = []
runtime_outputs = []
flag_candidates = []
blob_candidates = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
bitstring_re = re.compile(r"^[01]{24,}$")
hex_re = re.compile(r"^[0-9a-fA-F]{24,}$")
base64_re = re.compile(r"^[A-Za-z0-9+/=]{24,}$")

interpreter_by_suffix = {
    ".py": [["python3"], ["python"]],
    ".sh": [["bash"], ["sh"]],
    ".bash": [["bash"]],
    ".zsh": [["zsh"], ["bash"]],
    ".js": [["node"]],
    ".mjs": [["node"]],
    ".cjs": [["node"]],
    ".rb": [["ruby"]],
    ".pl": [["perl"]],
    ".php": [["php"]],
    ".lua": [["lua"]],
}


def add_flag_candidates(text):
    for match in flag_re.findall(text):
        if match not in flag_candidates:
            flag_candidates.append(match)


def add_blob_candidates(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or len(stripped) < 24:
            continue
        if bitstring_re.match(stripped) or hex_re.match(stripped) or base64_re.match(stripped):
            if stripped not in blob_candidates:
                blob_candidates.append(stripped)


def available_command(candidates):
    for argv in candidates:
        binary = argv[0]
        if shutil.which(binary):
            return argv
    return None


if not files_root.exists():
    records.append({"type": "summary", "text": f"Runtime probe skipped: {files_root} does not exist."})
    records.append({"type": "note", "text": f"Challenge files root not found: {files_root}"})
else:
    notes_list.append("Runtime probe executes bundled scripts with container-level privileges and short timeouts.")
    if flag_format:
        notes_list.append(f"Expected flag format hint: {flag_format}")

    for relpath in source_files[:max_files]:
        path = files_root / relpath
        if not path.is_file():
            continue

        suffix = path.suffix.lower()
        command_candidates = interpreter_by_suffix.get(suffix)
        if not command_candidates:
            continue

        interpreter = available_command(command_candidates)
        if interpreter is None:
            notes_list.append(f"No interpreter available for {relpath} ({suffix}).")
            continue

        try:
            completed = subprocess.run(
                [*interpreter, str(path)],
                capture_output=True,
                text=True,
                cwd=str(files_root),
                timeout=8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            notes_list.append(f"Runtime probe timed out for {relpath}.")
            continue
        except Exception as exc:
            notes_list.append(f"Runtime probe failed for {relpath}: {type(exc).__name__}: {exc}")
            continue

        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        add_flag_candidates(stdout)
        add_flag_candidates(stderr)
        add_blob_candidates(stdout)
        add_blob_candidates(stderr)

        executed_scripts.append(relpath)
        runtime_outputs.append({
            "path": relpath,
            "interpreter": interpreter[0],
            "returncode": completed.returncode,
            "stdout_preview": stdout[:400],
            "stderr_preview": stderr[:200],
        })

records.extend({"type": "note", "text": note} for note in notes_list)
records.append({
    "type": "summary",
    "text": (
        f"Runtime probe completed for {len(executed_scripts)} script(s): "
        f"{len(flag_candidates)} flag candidate(s), {len(blob_candidates)} blob candidate(s)."
    ),
})
records.append({
    "type": "finding",
    "finding_id": "finding-runtime-probe",
    "title": "Bundled scripts executed for runtime analysis",
    "severity": "info",
    "description": f"Executed {len(executed_scripts)} bundled script artifact(s) to collect runtime output.",
    "asset_refs": ["challenge-files"],
    "evidence_refs": executed_scripts[:5],
    "metadata": {
        "source": "runtime_probe",
        "executed_scripts": executed_scripts,
        "runtime_outputs": runtime_outputs[:5],
    },
})

if blob_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-runtime-output-blobs",
        "title": "Runtime output exposed encoded blob candidates",
        "severity": "medium",
        "description": f"Recovered {len(blob_candidates)} long runtime output blob(s) worth deeper analysis.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": blob_candidates[:5],
        "metadata": {
            "source": "runtime_probe",
            "blob_candidates": blob_candidates[:10],
        },
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-runtime-output-flags",
        "title": "Flag candidate recovered from runtime output",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from script runtime output.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {
            "source": "runtime_probe",
            "flag_candidates": flag_candidates[:10],
        },
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "executed_scripts": executed_scripts,
    "runtime_outputs": runtime_outputs[:10],
    "blob_candidates": blob_candidates[:10],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Review runtime output for encoded blobs, prompts, or challenge hints.",
        "Validate any flag-like token before submission.",
        "Escalate blob candidates into deeper computation analysis if needed.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "source_files": request.metadata.get("source_files", []),
        "max_files": request.metadata.get("max_files", 8),
        "flag_format": request.metadata.get("flag_format"),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
