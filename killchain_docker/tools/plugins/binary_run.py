"""Binary execution probe — run a bundled binary in a sandbox.

Generic CTF helper: many challenges ship a binary whose runtime behaviour
is the actual algorithm (e.g. XOR-cipher binaries are self-inverse so
``./stfu cipher.bin`` decrypts back to plaintext).  Reading the binary's
disassembly is one way to recover the algorithm; *running* it in a
controlled way is the other, and often the cheaper one.

Design constraints (kept algorithm-agnostic):

* The original ``challenge.files`` directory is treated read-only.  Every
  binary + every challenge file is COPIED into ``/tmp/binrun-<pid>/`` so
  any in-place rewrite the binary does cannot corrupt the source corpus.
* A small list of canonical invocations is tried per binary: no-args,
  ``--help`` / ``-h``, each non-binary challenge file passed positionally,
  and stdin-piped variants.  Capped at ~6 invocations / 15 s each so the
  tool stays bounded.
* Any file created or modified during a run is captured (size, mode, hex
  preview) because many CTF binaries decrypt by rewriting the input file
  in place.
* Output is JSONL records compatible with the existing tool framework.
"""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FILE_TARGETS_SNIPPET

TOOL_NAME = "binary_run"

# Triple-quoted strings inside SCRIPT will close the outer ``r"""..."""`` —
# use only ``#`` comments inside the embedded script.
SCRIPT = r"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
binary_files = payload.get("binary_files") or []
all_challenge_files = payload.get("challenge_files") or []
max_files = int(payload.get("max_files", 3))
per_invocation_timeout_s = int(payload.get("per_invocation_timeout_s", 15))
max_invocations_per_binary = int(payload.get("max_invocations_per_binary", 6))
# Per-stream byte caps so a chatty binary cannot blow up the prompt.
STDOUT_PREVIEW_BYTES = 1800
STDERR_PREVIEW_BYTES = 1200
FILE_PREVIEW_BYTES = 800

records = []
inspected = []
binary_runs = {}
flag_candidates = []

# Cheap regex for ``prefix{body}`` flag tokens in any stdout or new file.
import re as _re
flag_re = _re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")


if not binary_files:
    records.append({"type": "summary", "text": "Binary run failed: missing required metadata.binary_files."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_binaries": [], "binary_runs": {}, "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)


def _hex_preview(b, limit):
    if not b:
        return ""
    b = bytes(b[:limit])
    parts = []
    for i in range(0, len(b), 16):
        chunk = b[i:i+16]
        hexed = " ".join("%02x" % c for c in chunk)
        ascii_ = "".join(chr(c) if 32 <= c <= 126 else "." for c in chunk)
        parts.append("%04x  %-47s  %s" % (i, hexed, ascii_))
    out = "\n".join(parts)
    if len(b) >= limit:
        out += "\n... [truncated]"
    return out


def _snapshot_dir(d):
    out = {}
    for root, _dirs, files in os.walk(d):
        for f in files:
            p = Path(root) / f
            try:
                st = p.stat()
            except OSError:
                continue
            out[str(p.relative_to(d))] = (st.st_size, st.st_mtime_ns)
    return out


def _read_bytes(p, n):
    try:
        with open(p, "rb") as fh:
            return fh.read(n)
    except OSError:
        return b""


def _classify_text(buf):
    # Decide if a byte buffer is "printable text" or "binary blob".
    if not buf:
        return "empty", ""
    try:
        text = buf.decode("utf-8", errors="strict")
        printable = sum(1 for c in text if 32 <= ord(c) <= 126 or c in "\r\n\t")
        ratio = printable / len(text) if text else 0
        if ratio >= 0.92:
            return "text", text[:FILE_PREVIEW_BYTES]
    except UnicodeDecodeError:
        pass
    return "binary", _hex_preview(buf, FILE_PREVIEW_BYTES)


def _build_invocations(binary_path, candidate_inputs):
    # Each entry: (label, argv_after_binary, stdin_path_or_None)
    inv = []
    inv.append(("no-args", [], None))
    inv.append(("--help", ["--help"], None))
    inv.append(("-h", ["-h"], None))
    for inp in candidate_inputs:
        inv.append(("with " + inp.name, [str(inp)], None))
    for inp in candidate_inputs[:1]:
        inv.append(("stdin from " + inp.name, [], str(inp)))
    return inv[:max_invocations_per_binary]


targets = _resolve_file_targets(files_root, binary_files, max_files=max_files, kind="binary")
for target in targets:
    relpath = target["display"]
    bin_src = Path(target["path"])
    inspected.append(relpath)

    workdir = Path(tempfile.mkdtemp(prefix="binrun-"))
    try:
        # Copy binary into workdir, set executable.
        bin_local = workdir / Path(relpath).name
        shutil.copy2(bin_src, bin_local)
        bin_local.chmod(bin_local.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

        # Copy non-binary challenge files in too (ciphertexts, configs, etc).
        candidate_inputs = []
        for other in all_challenge_files:
            if other == relpath:
                continue
            src = files_root / other
            if not src.is_file():
                continue
            dst = workdir / Path(other).name
            try:
                shutil.copy2(src, dst)
            except OSError:
                continue
            candidate_inputs.append(dst)

        invocations = _build_invocations(bin_local, candidate_inputs)

        runs = []
        for label, argv, stdin_path in invocations:
            before = _snapshot_dir(workdir)
            argv_full = ["./" + bin_local.name] + argv
            stdin_handle = None
            if stdin_path is not None:
                try:
                    stdin_handle = open(stdin_path, "rb")
                except OSError:
                    continue
            t0 = time.time()
            timed_out = False
            try:
                res = subprocess.run(
                    argv_full,
                    cwd=str(workdir),
                    stdin=stdin_handle,
                    capture_output=True,
                    timeout=per_invocation_timeout_s,
                    check=False,
                )
                rc = res.returncode
                so = res.stdout or b""
                se = res.stderr or b""
            except subprocess.TimeoutExpired as exc:
                rc = -1
                so = exc.stdout or b""
                se = (exc.stderr or b"") + ("\n[binary_run] timeout after %ds" % per_invocation_timeout_s).encode()
                timed_out = True
            except Exception as exc:
                rc = -1
                so = b""
                se = ("[binary_run] exec error: %s" % exc).encode()
            finally:
                if stdin_handle is not None:
                    try:
                        stdin_handle.close()
                    except Exception:
                        pass
            elapsed = time.time() - t0

            after = _snapshot_dir(workdir)
            new_files = []
            for fname, (size_now, mtime_now) in after.items():
                if fname not in before:
                    p = workdir / fname
                    buf = _read_bytes(p, FILE_PREVIEW_BYTES * 2)
                    kind, preview = _classify_text(buf)
                    new_files.append({
                        "name": fname,
                        "size": size_now,
                        "kind": kind,
                        "preview": preview,
                    })
                    # Mine flag candidates from any text-looking new file.
                    if kind == "text":
                        for m in flag_re.findall(preview):
                            if m not in flag_candidates:
                                flag_candidates.append(m)
            changed_files = []
            for fname, (size_now, mtime_now) in after.items():
                if fname not in before:
                    continue
                size_before, mtime_before = before[fname]
                if size_before == size_now and mtime_before == mtime_now:
                    continue
                # Skip the executable itself unless it is the only changed file;
                # self-modifying unpackers are less useful than transformed
                # challenge inputs, but still capture them when present.
                p = workdir / fname
                buf = _read_bytes(p, FILE_PREVIEW_BYTES * 2)
                kind, preview = _classify_text(buf)
                changed_files.append({
                    "name": fname,
                    "size_before": size_before,
                    "size": size_now,
                    "kind": kind,
                    "preview": preview,
                })
                if kind == "text":
                    for m in flag_re.findall(preview):
                        if m not in flag_candidates:
                            flag_candidates.append(m)

            # Also mine flag candidates from stdout text.
            stdout_text = ""
            try:
                stdout_text = so.decode("utf-8", "replace")
                for m in flag_re.findall(stdout_text):
                    if m not in flag_candidates:
                        flag_candidates.append(m)
            except Exception:
                pass

            run_entry = {
                "label": label,
                "argv": argv_full,
                "stdin_from": Path(stdin_path).name if stdin_path else None,
                "returncode": rc,
                "elapsed_s": round(elapsed, 3),
                "timed_out": timed_out,
                "stdout_bytes": len(so),
                "stderr_bytes": len(se),
                "stdout_preview": stdout_text[:STDOUT_PREVIEW_BYTES],
                "stderr_preview": se.decode("utf-8", "replace")[:STDERR_PREVIEW_BYTES],
                "new_files": new_files,
                "changed_files": changed_files,
            }
            runs.append(run_entry)

        binary_runs[relpath] = {
            "binary": relpath,
            "workdir_template": str(workdir.name),
            "invocations": runs,
        }
        records.append({
            "type": "note",
            "text": (
                "Ran " + relpath + " " + str(len(runs)) + " invocation(s); "
                "produced " + str(sum(len(r["new_files"]) for r in runs)) + " new file(s) and "
                "modified " + str(sum(len(r.get("changed_files", [])) for r in runs)) + " existing file(s)."
            ),
        })
    finally:
        # Always clean the sandbox; the evidence is already serialized.
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass

if not inspected:
    records.append({"type": "summary", "text": "Binary run failed: no requested binary files could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "binary_files": binary_files[:max_files], "inspected_binaries": [], "binary_runs": {}, "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

records.append({
    "type": "summary",
    "text": (
        "Binary run probe completed for " + str(len(inspected)) + " binary(ies); "
        "captured " + str(sum(len(d['invocations']) for d in binary_runs.values()))
        + " invocation(s) and " + str(len(flag_candidates)) + " flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-binary-run",
    "title": "Binary execution evidence collected",
    "severity": "info",
    "description": (
        "Ran " + str(len(inspected)) + " bundled binary artifact(s) in a /tmp sandbox; "
        "see output_context['binary_runs'] for per-invocation stdout/stderr "
        "and any new files the binary produced."
    ),
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "binary_run", "inspected": inspected},
})

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-binary-run-flags",
        "title": "Flag-like token observed during binary execution",
        "severity": "high",
        "description": "Recovered " + str(len(flag_candidates)) + " flag candidate(s) from binary execution.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "binary_run", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_binaries": inspected,
    "binary_runs": binary_runs,
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Read every invocation's stdout_preview / stderr_preview to learn what the binary expects.",
        "When 'new_files' or 'changed_files' contains text, inspect it first; in-place rewrites often hold the decrypted flag.",
        "If '--help' or '-h' returned usage info, re-run with the documented flags via script.execute.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""

SCRIPT = SHARED_FILE_TARGETS_SNIPPET + SCRIPT


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "binary_files": request.metadata.get("binary_files", []),
        "challenge_files": request.metadata.get("challenge_files", []),
        "max_files": request.metadata.get("max_files", 3),
        "per_invocation_timeout_s": request.metadata.get("per_invocation_timeout_s", 15),
        "max_invocations_per_binary": request.metadata.get("max_invocations_per_binary", 6),
    }
    return ["-c", SCRIPT, json.dumps(payload)]

def build_tool_output(request, result, parsed):
    from killchain_docker.tools.output_builder import base_output, extract_flag_candidates, extract_artifacts, extract_binary_run_artifacts
    ctx = parsed.output_context or {}
    source = request.capability or request.tool_name
    output = base_output(request, result, parsed)
    output.flag_candidates = extract_flag_candidates(ctx, source=source, flag_format=request.metadata.get("flag_format"))
    output.artifacts = extract_artifacts(ctx, source=source, keys={"inspected_binaries": "binary"}) + extract_binary_run_artifacts(ctx, source=source)
    return output
