"""Execute LLM-generated solver scripts inside the agent container."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FLAG_DETECTION_SNIPPET

TOOL_NAME = "solver_execution"

# The script header parses the JSON payload and sets up the regex objects used
# by the body. The shared flag-detection snippet (concatenated at build time)
# defines `_plausible_flag` / `_near_miss_flag`.
_SCRIPT_HEADER = r"""
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

# Maximum bytes per challenge file we'll snapshot into memory for restore.
# Files larger than this are skipped (we only chmod-protect them).  4 MiB
# easily covers every NYU dataset challenge file we've seen.
_CHALLENGE_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024

payload = json.loads(sys.argv[1])
solver_code = payload.get("solver_code", "")
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
timeout_s = int(payload.get("timeout_s", 30))
flag_format = str(payload.get("flag_format") or "")
solver_language = str(payload.get("solver_language") or "python")
challenge_files = payload.get("challenge_files") or []

records = []
notes_list = []
flag_candidates = []
near_miss_candidates = []

# Generic shape: ``prefix{body}`` with printable ASCII body of 4-200 chars.
flag_re = re.compile(r"[A-Za-z0-9_]+\{[ -~]{4,200}\}")
# Same shape but allows non-printable characters in the body, used for "garbled
# decrypt" near-miss reporting only.
near_miss_re = re.compile(r"[A-Za-z0-9_]{2,}\{[^\n]{4,200}\}")

# When the challenge metadata advertises a specific format prefix (e.g.
# ``key{...}``), we accept only that prefix as a candidate and ignore generic
# ``flag{}`` matches that may appear in source code echoed back from solver
# scripts (e.g. ``re.findall(r'flag\{...}')`` literals).
format_prefix_re = None
if flag_format and "{" in flag_format:
    ff_prefix = flag_format.split("{", 1)[0].strip()
    if ff_prefix and ff_prefix.isalnum():
        format_prefix_re = re.compile(
            re.escape(ff_prefix) + r"\{[ -~]{1,200}\}"
        )

# Bare-token mode: when the actual challenge flag is NOT in ``prefix{body}``
# shape (NYU dataset has these — e.g. CSAW 2013 stfu uses
# ``STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME``).  The runner signals this
# mode by passing ``flag_format == ""``.  In that mode we additionally
# harvest single-token candidates from the tail of stdout (NEVER stderr,
# since solvers print debug logs / tracebacks / source echoes there).
_bare_token_mode = not flag_format.strip()
_bare_token_re = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}$")
_py_exception_re = re.compile(r"^(?:[A-Z][A-Za-z0-9]*)+(?:Error|Exception|Warning)$")
"""

# Body executes the user solver and harvests flag candidates from its output:
#
# 1. Always attempt prefix{body}-shaped extraction.  Apply the format-specific
#    prefix first when one is known, then the generic ``\w+\{...\}`` regex.
# 2. Bare-token fallback (only when ``flag_format`` is empty AND no prefix
#    candidate was found): scan the stdout tail for single-token answers
#    matching ``[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}``.  Stricter than the
#    pre-refactor "trailing line" heuristic — that one used to flood the
#    queue with garbage like ``"FileNotFoundError: ..."`` or
#    ``"with open('x') as f:"``.  Stderr is never scanned because solvers
#    print debug logs / tracebacks / source echoes there.
_SCRIPT_BODY = r"""
def _looks_like_solver_source(text):
    # Return True for lines that are clearly echoed source code, not flags.
    needles = (
        # Calls into common Python idioms most solvers use:
        "re.findall", "re.search", "re.match",
        "subprocess.", "os.system", "shell=True",
        "open(", "import ", "from ",
        # Flag pattern source-code references:
        "{thing}", "{tablename}", "{fieldname}",
        # Format-string artifacts:
        "{0}", "{1}", "{name}", "{flag}",
    )
    low = text.lower()
    return any(needle in text or needle.lower() in low for needle in needles)


def _record_candidate(match, bucket):
    if match in bucket:
        return
    if not _plausible_flag(match):
        return
    if _looks_like_solver_source(match):
        return
    bucket.append(match)


def _record_near_miss(match):
    if match in flag_candidates or match in near_miss_candidates:
        return
    if not _near_miss_flag(match):
        return
    if _looks_like_solver_source(match):
        return
    near_miss_candidates.append(match)


def _harvest_bare_token_candidates(text, max_take=3):
    # Tail-of-stdout harvest for non-prefix flag formats. Strict single-token
    # filter: no whitespace, alnum + ``_-.`` only, 12-200 chars, not a Python
    # exception name like ``FileNotFoundError``.
    if not text:
        return []
    out = []
    raw_lines = str(text).replace("\r\n", "\n").split("\n")
    for raw in reversed([ln.strip() for ln in raw_lines if ln.strip()][-20:]):
        if not _bare_token_re.fullmatch(raw):
            continue
        if _py_exception_re.fullmatch(raw):
            continue
        if raw in out or raw in flag_candidates:
            continue
        out.append(raw)
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

stdout = ""
stderr = ""
returncode = -1
_challenge_restore = []  # list[(path_str, original_mode_only)]
_challenge_snapshots = []  # list[(path_str, original_mode_only, sha256, bytes|None)]

try:
    for raw in challenge_files:
        name = str(raw).strip()
        if not name or "/" in name or "\\" in name or ".." in name:
            continue
        if Path(name).parts != (name,):
            continue
        cpath = files_root / name
        if not cpath.is_file():
            continue
        # Stat the file so we can restore mode + detect content tampering.
        try:
            st = cpath.stat()
        except OSError as exc:
            notes_list.append(
                f"Snapshot failed for {name}: cannot stat ({exc.__class__.__name__})."
            )
            continue
        mode_only = stat.S_IMODE(st.st_mode)
        _challenge_restore.append((str(cpath), mode_only))

        # Snapshot the file contents in RAM so we can restore byte-for-byte if
        # the solver overwrites it (e.g. running ``stfu flag.stfu`` in-place
        # truncates the file from 25316 bytes back to 16).  Hash either way so
        # we always notice a changed file even when we couldn't snapshot.
        snapshot_bytes = None
        try:
            with open(cpath, "rb") as f:
                head = f.read(_CHALLENGE_SNAPSHOT_MAX_BYTES + 1)
            if len(head) <= _CHALLENGE_SNAPSHOT_MAX_BYTES:
                snapshot_bytes = head
                digest = hashlib.sha256(head).hexdigest()
            else:
                # Too large to safely keep in RAM — hash by streaming so we
                # can still detect a change.
                h = hashlib.sha256()
                with open(cpath, "rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                digest = h.hexdigest()
                notes_list.append(
                    f"Snapshot for {name}: file > {_CHALLENGE_SNAPSHOT_MAX_BYTES} bytes; "
                    "hash recorded but content not held in RAM (no automatic restore)."
                )
        except OSError as exc:
            notes_list.append(
                f"Snapshot read failed for {name}: {exc.__class__.__name__}."
            )
            continue
        _challenge_snapshots.append((str(cpath), mode_only, digest, snapshot_bytes))

        # First line of defence: chmod read-only.  When the container user
        # owns the file this DOES prevent the binary's fopen("flag.stfu","wb")
        # call from succeeding.  When chmod fails (root-owned mount, fs that
        # doesn't honour mode, etc.) we emit a visible note so the failure
        # isn't silent — the snapshot+restore below is the real backstop.
        exec_any = st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        try:
            os.chmod(cpath, 0o555 if exec_any else 0o444)
        except OSError as exc:
            notes_list.append(
                f"chmod read-only failed for {name}: {exc.__class__.__name__}: {exc}; "
                "relying on content-snapshot restore."
            )

    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    try:
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

        # Prefer format-specific prefix when metadata gives us one. Otherwise fall
        # back to the generic prefix{body} pattern.
        for text in (stdout, stderr):
            if format_prefix_re is not None:
                for match in format_prefix_re.findall(text):
                    _record_candidate(match, flag_candidates)
            for match in flag_re.findall(text):
                _record_candidate(match, flag_candidates)

        # Bare-token mode: harvest single-token candidates from stdout tail when
        # the challenge uses a non-prefix flag (e.g. ``STFU_THIS_CHALLENGE_...``).
        # Only fired when no prefix-shaped candidate was found, so it stays a
        # supplement rather than another source of validation spam.
        if _bare_token_mode and not flag_candidates:
            for token in _harvest_bare_token_candidates(stdout):
                if token not in flag_candidates:
                    flag_candidates.append(token)

        # Bracket-span fallback (csawpad fix): when extraction finds no canonical
        # ``prefix{body}`` candidate, but the solver printed a free-floating
        # ``{body}`` span (e.g. ``MY key for you is {And yes the nsa can read
        # this to}``), wrap the body with the challenge's flag_format prefix
        # plus a few common CTF prefixes so the equality-validator can confirm.
        if not flag_candidates:
            ff_prefix = None
            if flag_format and "{" in flag_format:
                ff_prefix = flag_format.split("{", 1)[0].strip() or None
            span_candidates = _bracket_span_candidates(stdout, ff_prefix)
            for cand in span_candidates:
                if cand not in flag_candidates:
                    flag_candidates.append(cand)

        # Near-miss capture only when no real candidate was found, so we don't spam
        # the validator with both shapes.
        if not flag_candidates:
            for text in (stdout, stderr):
                for match in near_miss_re.findall(text):
                    _record_near_miss(match)

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
    # Snapshot+restore: walk every challenge file we hashed before the run,
    # recompute its sha256, and if it changed restore from the in-memory
    # snapshot.  This is the backstop that protects against in-place
    # rewrites (e.g. the stfu binary overwriting flag.stfu when invoked
    # against itself).  Runs even when chmod was a no-op above.
    for path_str, _orig_mode, recorded_digest, snapshot_bytes in _challenge_snapshots:
        if snapshot_bytes is None:
            continue
        try:
            with open(path_str, "rb") as f:
                current_digest = hashlib.sha256(f.read()).hexdigest()
        except OSError as exc:
            notes_list.append(
                f"Post-run hash failed for {Path(path_str).name}: "
                f"{exc.__class__.__name__}: {exc}; skipping restore."
            )
            continue
        if current_digest == recorded_digest:
            continue
        try:
            os.chmod(path_str, 0o600)  # ensure we can write
            with open(path_str, "wb") as f:
                f.write(snapshot_bytes)
            notes_list.append(
                f"Solver overwrote challenge file {Path(path_str).name}; "
                f"restored from snapshot ({len(snapshot_bytes)} bytes)."
            )
        except OSError as exc:
            notes_list.append(
                f"Restore failed for {Path(path_str).name}: "
                f"{exc.__class__.__name__}: {exc}."
            )

    # Restore the original permission bits last so the file ends in the
    # same state the orchestrator passed in.
    for path_str, mode_only in reversed(_challenge_restore):
        try:
            os.chmod(path_str, mode_only)
        except OSError:
            pass
    try:
        os.unlink(solver_path)
    except OSError:
        pass

records.extend({"type": "note", "text": note} for note in notes_list)

result_severity = "high" if flag_candidates else ("medium" if returncode == 0 else "info")
if returncode == 0 and flag_candidates:
    summary_state = "succeeded"
elif returncode == 0:
    summary_state = "ran without recovering a flag"
else:
    summary_state = f"failed (exit {returncode})"
records.append({
    "type": "summary",
    "text": (
        f"Solver execution {summary_state}: "
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
    raw_cf = request.metadata.get("challenge_files") or []
    challenge_files = [str(x).strip() for x in raw_cf if str(x).strip()]
    payload = {
        "solver_code": request.metadata.get("solver_code", ""),
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "timeout_s": request.metadata.get("timeout_s", 30),
        "flag_format": request.metadata.get("flag_format"),
        "solver_language": request.metadata.get("solver_language", "python"),
        "challenge_files": challenge_files,
    }
    return ["-c", SCRIPT, json.dumps(payload)]
