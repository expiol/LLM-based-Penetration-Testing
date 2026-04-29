"""Execute LLM-generated solver scripts inside the agent container."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest
from nyuctf_mutil_killchain.tools.plugins._shared import SHARED_FLAG_DETECTION_SNIPPET

TOOL_NAME = "solver_execution"

_SCRIPT_HEADER = r"""
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

payload = json.loads(sys.argv[1])
solver_code = payload.get("solver_code", "")
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
timeout_s = int(payload.get("timeout_s", 30))
flag_format = str(payload.get("flag_format") or "")
solver_language = str(payload.get("solver_language") or "python")

records = []
notes_list = []
flag_candidates = []
near_miss_candidates = []
flag_re = re.compile(r"[A-Za-z0-9_]{2,}\{[ -~]{4,200}\}")
near_miss_re = re.compile(r"[A-Za-z0-9_]{2,}\{[^\n]{4,200}\}")

# Build a format-specific regex if flag_format specifies a prefix (e.g. "key{...}")
format_prefix_re = None
if flag_format and "{" in flag_format:
    ff_prefix = flag_format.split("{", 1)[0].strip()
    if ff_prefix and ff_prefix.isalnum():
        format_prefix_re = re.compile(
            re.escape(ff_prefix) + r"\{[ -~]{1,200}\}"
        )
"""

_SCRIPT_BODY = r"""
def _solver_regex_noise(m):
    # Reject prefix{...} substrings copied from echoed exploit source, not real flags.
    low = m.lower()
    needles = (
        "re.findall",
        "matches =",
        "print(",
        " in binary",
        " in response",
        "\\\\",
        "rb'",
        "r\"",
        "payload",
        "{thing}",
        "{tablename}",
        "{fieldname}",
    )
    return any(n in low for n in needles)


def _plain_tail_flag_candidates(text, max_take=4):
    # Bare-token or short-sentence flags (NYU bench) from trailing stdout lines.
    if not text or not str(text).strip():
        return []
    lines = [ln.strip() for ln in str(text).replace("\r\n", "\n").split("\n") if ln.strip()]
    tail = lines[-40:] if len(lines) > 40 else lines
    out = []
    bad_starts = (
        "traceback", "during ", "  file", "file \"", "import ", "from ", "def ", "class ",
        "===", "---", "note:", "debug:", "error:", "warning:", "http://", "https://",
    )
    for line in reversed(tail):
        if len(line) < 12 or len(line) > 220:
            continue
        low = line.lower()
        if any(low.startswith(p) for p in bad_starts):
            continue
        if "re.findall" in line or "matches =" in line:
            continue
        printable = sum(1 for ch in line if ch.isprintable())
        if not line or printable / len(line) < 0.85:
            continue
        if re.fullmatch(r"[A-Za-z0-9_]{12,}", line) or (
            "{" not in line and 16 <= len(line) <= 120 and 2 <= line.count(" ") <= 24
        ):
            if line not in out:
                out.append(line)
        if len(out) >= max_take:
            break
    return out

if not solver_code.strip():
    records.append({"type": "summary", "text": "Solver execution skipped: no solver code provided."})
    records.append({"type": "output_context", "flag_candidates": [], "stdout": "", "stderr": "", "returncode": -1})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(0)

suffix_map = {
    "python": ".py",
    "bash": ".sh",
    "sh": ".sh",
    "javascript": ".js",
    "node": ".js",
    "ruby": ".rb",
    "perl": ".pl",
    "sage": ".sage",
}
interpreter_map = {
    "python": ["python3"],
    "bash": ["bash"],
    "sh": ["sh"],
    "javascript": ["node"],
    "node": ["node"],
    "ruby": ["ruby"],
    "perl": ["perl"],
    "sage": ["sage", "-python"],
}

suffix = suffix_map.get(solver_language, ".py")
interpreter = interpreter_map.get(solver_language, ["python3"])

with tempfile.NamedTemporaryFile(
    mode="w", suffix=suffix, dir=str(files_root), delete=False, prefix="_solver_"
) as tmp:
    tmp.write(solver_code)
    solver_path = tmp.name

try:
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    completed = subprocess.run(
        [*interpreter, solver_path],
        capture_output=True,
        text=True,
        cwd=str(files_root),
        timeout=timeout_s,
        check=False,
        env=env,
    )
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    returncode = completed.returncode

    for text in (stdout, stderr):
        # First try format-specific prefix if available (e.g. key{...})
        if format_prefix_re:
            for match in format_prefix_re.findall(text):
                if (
                    match not in flag_candidates
                    and _plausible_flag(match)
                    and not _solver_regex_noise(match)
                ):
                    flag_candidates.append(match)
        # Then try generic flag pattern
        for match in flag_re.findall(text):
            if (
                match not in flag_candidates
                and _plausible_flag(match)
                and not _solver_regex_noise(match)
            ):
                flag_candidates.append(match)

    ff_norm = flag_format.strip().lower()
    if ff_norm in ("", "not provided"):
        seen_fc = set(flag_candidates)
        for text in (stdout, stderr):
            for plain in _plain_tail_flag_candidates(text):
                if plain not in seen_fc:
                    flag_candidates.append(plain)
                    seen_fc.add(plain)

    if not flag_candidates:
        for text in (stdout, stderr):
            for match in near_miss_re.findall(text):
                if (
                    match not in flag_candidates
                    and match not in near_miss_candidates
                    and _near_miss_flag(match)
                    and not _solver_regex_noise(match)
                ):
                    near_miss_candidates.append(match)

    notes_list.append(f"Solver script executed with {interpreter[0]}, exit code {returncode}.")
    if flag_candidates:
        notes_list.append(f"Recovered {len(flag_candidates)} flag candidate(s) from solver output.")
    if near_miss_candidates:
        notes_list.append(
            f"Detected {len(near_miss_candidates)} near-miss flag pattern(s) with non-printable characters."
        )

except subprocess.TimeoutExpired:
    stdout = ""
    stderr = f"Solver script timed out after {timeout_s}s."
    returncode = -1
    notes_list.append(stderr)
except Exception as exc:
    stdout = ""
    stderr = f"Solver execution error: {type(exc).__name__}: {exc}"
    returncode = -1
    notes_list.append(stderr)
finally:
    try:
        os.unlink(solver_path)
    except OSError:
        pass

records.extend({"type": "note", "text": note} for note in notes_list)

result_severity = "high" if flag_candidates else ("medium" if returncode == 0 else "info")
records.append({
    "type": "summary",
    "text": (
        f"Solver execution {'succeeded' if returncode == 0 else 'completed'}: "
        f"exit code {returncode}, {len(flag_candidates)} flag candidate(s)."
    ),
})
records.append({
    "type": "finding",
    "finding_id": "finding-solver-execution",
    "title": "LLM-generated solver script executed",
    "severity": result_severity,
    "description": (
        f"Executed LLM-generated {solver_language} solver script. "
        f"Exit code: {returncode}. Flag candidates: {len(flag_candidates)}."
    ),
    "asset_refs": ["challenge-files"],
    "evidence_refs": flag_candidates[:5],
    "metadata": {
        "source": "solver_execution",
        "returncode": returncode,
        "stdout_preview": stdout[:2000],
        "stderr_preview": stderr[:1000],
        "flag_candidates": flag_candidates[:10],
        "near_miss_candidates": near_miss_candidates[:5],
    },
})
records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "solver_language": solver_language,
    "returncode": returncode,
    "stdout": stdout[:8000],
    "stderr": stderr[:4000],
    "flag_candidates": flag_candidates[:10],
    "near_miss_candidates": near_miss_candidates[:5],
    "manual_checks": [
        "Review solver stdout for partial flag fragments or encoded data.",
        "Check stderr for missing dependencies that could be installed.",
        "If solver failed, refine the approach and regenerate.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""

SCRIPT = _SCRIPT_HEADER + SHARED_FLAG_DETECTION_SNIPPET + _SCRIPT_BODY


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "solver_code": request.metadata.get("solver_code", ""),
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "timeout_s": request.metadata.get("timeout_s", 30),
        "flag_format": request.metadata.get("flag_format"),
        "solver_language": request.metadata.get("solver_language", "python"),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
