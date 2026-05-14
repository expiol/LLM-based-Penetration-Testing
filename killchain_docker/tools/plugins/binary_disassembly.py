"""Binary disassembly tool (objdump-based).

A generic capability companion to :mod:`binary_triage`: where triage runs
``strings``/``file`` for fast first-pass, this tool runs ``objdump`` to
produce real disassembly + ``.rodata`` extraction + cross-reference between
strings and the functions that load them.

Design notes (kept algorithm-agnostic on purpose):

* Architecture / ABI is auto-detected from the ELF header by ``objdump``;
  the script does not branch on x86 vs ARM vs MIPS so any platform GNU
  binutils supports works without code change.
* "Interesting" functions are picked by (a) reachability from ``main`` /
  ``_start`` (using objdump's symbol table for non-stripped binaries),
  and (b) presence of ``.rodata`` string xrefs (call sites that load a
  printable constant — usually the error-message line in the algorithm).
  This is not LFSR-specific; it is the standard "find which function
  prints this error string" workflow that works for every binary CTF
  category.
* Output is capped to ~10 KB so it fits in planner and worker prompts.
* When the binary is non-ELF or ``objdump`` is missing, the tool returns
  a clear ``unsupported`` note rather than crashing.
"""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FILE_TARGETS_SNIPPET

TOOL_NAME = "binary_disassembly"

# IMPORTANT: the embedded script CANNOT contain triple-quoted strings — they
# would close this outer ``r"""..."""``.  Use ``#`` comments instead.
SCRIPT = r"""
import json
import re
import subprocess
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
binary_files = payload.get("binary_files") or []
max_files = int(payload.get("max_files", 4))

# Per-binary budgets (chars) that bound prompt growth.  Sized so a typical
# stripped i386 CTF binary (~10-20KB code) fits without truncating the
# crypto/decryption loop in the middle.  Even 4 binaries together stay
# under ~80 KB which is comfortably below the prompt budget.
MAX_RODATA_CHARS = 2400
MAX_FUNCTIONS_PER_BINARY = 12
MAX_FUNC_BODY_CHARS = 1800
MAX_DISASM_CHARS_PER_BINARY = 18000


def _run(args, timeout=20):
    # Subprocess wrapper that never raises; returns (stdout, stderr, rc).
    try:
        res = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return res.stdout or "", res.stderr or "", res.returncode
    except Exception as exc:
        return "", f"subprocess error: {exc}", -1


def _has_objdump():
    _, _, rc = _run(["objdump", "--version"], timeout=5)
    return rc == 0


def _file_type(path):
    out, _, _ = _run(["file", "-b", str(path)], timeout=5)
    return out.strip()


def _readelf_sections(path):
    out, _, rc = _run(["readelf", "-S", str(path)], timeout=10)
    if rc != 0:
        return []
    sections = []
    section_re = re.compile(r"\[\s*\d+\]\s+(\S+)")
    for line in out.splitlines():
        m = section_re.search(line)
        if m:
            sections.append(m.group(1))
    return sections[:80]


def _strings_sample(path):
    out, _, _ = _run(["strings", "-a", "-n", "6", str(path)], timeout=10)
    return out[:12000]


def _binary_traits(path, ftype, symbols):
    sections = _readelf_sections(path)
    string_sample = _strings_sample(path)
    haystack = "\n".join([ftype, "\n".join(sections), string_sample]).lower()
    go_markers = (
        ".gopclntab", ".note.go.buildid", "go build id", "runtime.main",
        "runtime.", "main.main", "go.itab.", "go.string.",
    )
    arch = "unknown"
    lowered = ftype.lower()
    if "intel 80386" in lowered or "80386" in lowered:
        arch = "i386"
    elif "x86-64" in lowered or "x86_64" in lowered:
        arch = "x86_64"
    elif "arm" in lowered:
        arch = "arm"
    elif "mips" in lowered:
        arch = "mips"
    stripped = (not bool(symbols)) and ("not stripped" not in lowered)
    return {
        "file_type": ftype,
        "arch": arch,
        "stripped": stripped,
        "symbol_table_present": bool(symbols),
        "sections": sections[:20],
        "go_like": any(marker in haystack for marker in go_markers),
        "go_markers_present": [
            marker for marker in go_markers if marker in haystack
        ][:8],
    }


def _symbol_table(path):
    # Return {addr_hex_no_leading_zeros: func_name} for FUNC-typed symbols.
    # Empty dict for stripped binaries.
    out, _, _ = _run(["objdump", "-t", str(path)], timeout=10)
    syms = {}
    func_re = re.compile(r"^([0-9a-f]+)\s+\S+\s+F\s+\S+\s+\S+\s+(\S+)$")
    for line in out.splitlines():
        m = func_re.match(line.strip())
        if not m:
            continue
        syms[m.group(1).lstrip("0") or "0"] = m.group(2)
    return syms


def _rodata(path):
    # Parse `objdump -s -j .rodata` hex+ASCII display into [(addr_int, str), ...].
    out, _, rc = _run(["objdump", "-s", "-j", ".rodata", str(path)], timeout=10)
    if rc != 0 or not out:
        return []
    entries = []
    row_re = re.compile(r"^\s+([0-9a-f]+)\s+([0-9a-f ]+?)\s\s([\S ]+)$")
    current_addr = None
    current_buf = bytearray()
    last_offset = None

    def _flush():
        if not current_buf:
            return
        offset = 0
        for chunk in current_buf.split(b"\x00"):
            if chunk and 4 <= len(chunk) <= 160:
                try:
                    txt = chunk.decode("utf-8", "replace")
                except Exception:
                    offset += len(chunk) + 1
                    continue
                if all(32 <= ord(c) <= 126 for c in txt):
                    entries.append((current_addr + offset, txt))
            offset += len(chunk) + 1

    for line in out.splitlines():
        m = row_re.match(line)
        if m is None:
            _flush()
            current_addr = None
            current_buf = bytearray()
            last_offset = None
            continue
        addr_int = int(m.group(1), 16)
        hex_bytes = m.group(2).replace(" ", "")
        if current_addr is None:
            current_addr = addr_int
            last_offset = addr_int
        elif addr_int != last_offset + len(current_buf):
            _flush()
            current_addr = addr_int
            current_buf = bytearray()
            last_offset = addr_int
        try:
            current_buf.extend(bytes.fromhex(hex_bytes))
        except ValueError:
            continue
    _flush()
    return entries


def _parse_disassembly(text):
    # Split `objdump -d` listing into {func_name: body_str}.
    funcs = {}
    cur_name = None
    cur_lines = []
    header_re = re.compile(r"^([0-9a-f]+)\s+<([^>]+)>:\s*$")
    for line in text.splitlines():
        m = header_re.match(line)
        if m:
            if cur_name is not None:
                funcs[cur_name] = "\n".join(cur_lines).strip()
            cur_name = m.group(2)
            cur_lines = [line.rstrip()]
            continue
        if cur_name is None:
            continue
        cur_lines.append(line.rstrip())
    if cur_name is not None and cur_lines:
        funcs[cur_name] = "\n".join(cur_lines).strip()
    return funcs


def _string_xrefs(funcs, rodata):
    # Map {func_name: [rodata_string, ...]} by word-bounded hex address scan.
    # Architecture-agnostic: every ABI loads constants via an immediate or
    # PC-relative move, and the address text appears verbatim in objdump
    # output.  Word-bounded so ``8048e9`` doesn't false-match ``8048e90``.
    xrefs = {fn: [] for fn in funcs}
    if not rodata:
        return xrefs
    for fn, body in funcs.items():
        seen = set()
        for addr, val in rodata:
            patterns = (
                "0x%x" % addr,
                "0x%08x" % addr,
            )
            if any(p in body for p in patterns):
                if val not in seen and len(seen) < 6:
                    xrefs[fn].append(val)
                    seen.add(val)
    return xrefs


def _is_noise_func(name):
    # Skip section markers (.init/.plt/.fini), PLT stubs, and known libc
    # boilerplate so the budget goes to real user code.  Note: ``.text``
    # is NOT noise — for fully-stripped binaries objdump labels the entire
    # code section as ``.text`` and that is exactly where user code lives.
    if not name:
        return True
    if name == ".text":
        return False
    if name.startswith("."):
        # .init / .plt / .fini are boilerplate.
        return True
    if name.endswith("@plt") or name.endswith("@@plt"):
        return True
    if name in {
        "_init", "_fini", "register_tm_clones",
        "deregister_tm_clones", "__do_global_dtors_aux", "frame_dummy",
        "__libc_csu_init", "__libc_csu_fini", "_dl_relocate_static_pie",
    }:
        return True
    return False


def _entry_set(symbols, funcs, xrefs):
    # Pick the "interesting" function names to keep, in priority order:
    #   1. ``main`` if present (the goal in non-stripped binaries).
    #   2. Functions with ``.rodata`` xrefs (these are usually where the
    #      algorithm lives — they print error messages / load magic).
    #   3. Largest non-noise function (stripped binaries: the user code is
    #      typically merged into one ``.text`` block, much bigger than PLT
    #      stubs and libc init wrappers).
    #   4. Mid-size, non-noise functions to fill remaining slots.
    #   5. ``_start`` as a last resort (entry into libc bootstrap chain).
    keep = []
    keep_set = set()

    def _add(name):
        if name in funcs and name not in keep_set and not _is_noise_func(name):
            keep.append(name)
            keep_set.add(name)

    _add("main")
    # xref-bearing functions next — these are the strongest "this is the algo" signal.
    xref_ranked = sorted(
        ((n, len(xrefs.get(n) or [])) for n in funcs.keys()),
        key=lambda kv: -kv[1],
    )
    for name, count in xref_ranked:
        if count == 0:
            break
        _add(name)
        if len(keep) >= MAX_FUNCTIONS_PER_BINARY:
            return keep
    # Largest non-noise body next — for stripped binaries with no rodata xrefs
    # detected (e.g. when the rodata addresses don't appear verbatim in the
    # disassembly because the binary uses GOT-based addressing), this reliably
    # finds the user-code block.
    size_ranked = sorted(
        ((name, len(body)) for name, body in funcs.items() if not _is_noise_func(name)),
        key=lambda kv: -kv[1],
    )
    for name, _size in size_ranked[:3]:
        _add(name)
        if len(keep) >= MAX_FUNCTIONS_PER_BINARY:
            return keep
    # Fill remaining budget with non-noise mid-size functions.
    for name, body in funcs.items():
        if name in keep_set:
            continue
        if _is_noise_func(name):
            continue
        if 80 < len(body) < MAX_FUNC_BODY_CHARS:
            keep.append(name)
            keep_set.add(name)
            if len(keep) >= MAX_FUNCTIONS_PER_BINARY:
                return keep
    # If we still have room and nothing matched, fall back to _start (worth a peek).
    if len(keep) < MAX_FUNCTIONS_PER_BINARY and "_start" in funcs and "_start" not in keep_set:
        keep.append("_start")
    return keep[:MAX_FUNCTIONS_PER_BINARY]


def _condense_function(body, budget=None):
    # Drop blanks / section markers, then trim to budget.  When the body
    # exceeds the budget, keep three slices (head, middle, tail) instead of
    # only head+tail.  The middle slice is critical for stripped binaries
    # where ``main`` and the algorithmic loop both live inside a single big
    # ``.text`` block; a head+tail-only strategy reliably loses the crypto
    # core in the middle.
    lines = []
    for raw in body.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith(";;") or stripped.startswith("Disassembly of"):
            continue
        lines.append(raw.rstrip())
    out = "\n".join(lines)
    if budget is None:
        budget = MAX_FUNC_BODY_CHARS
    if len(out) <= budget:
        return out
    marker = "\n    ; ... [truncated] ...\n"
    overhead = len(marker) * 2
    available = max(300, budget - overhead)
    head_budget = available // 3
    tail_budget = available // 3
    middle_budget = available - head_budget - tail_budget
    middle_start = max(head_budget, (len(out) - middle_budget) // 2)
    middle_end = middle_start + middle_budget
    return (
        out[:head_budget]
        + marker
        + out[middle_start:middle_end]
        + marker
        + out[-tail_budget:]
    )


def _analysis_windows(raw_disasm, rodata):
    # Small windows around bit/branch instructions and rodata address refs.
    # These are meant as navigation hints for stripped binaries where the
    # kept function is too large to include in full.
    lines = [line.rstrip() for line in raw_disasm.splitlines() if line.strip()]
    address_needles = []
    for addr, _value in rodata[:24]:
        address_needles.append("0x%x" % addr)
        address_needles.append("0x%08x" % addr)
    bit_ops = re.compile(r"\b(xor|shr|shl|sar|sal|rol|ror|and|test|cmp|jne|je|jmp)\b")
    anchors = []
    for idx, line in enumerate(lines):
        lowered = line.lower()
        if "@plt" in lowered:
            continue
        if bit_ops.search(lowered) or any(needle in lowered for needle in address_needles):
            anchors.append(idx)
    windows = []
    seen_ranges = set()
    for idx in anchors[:80]:
        start = max(0, idx - 5)
        end = min(len(lines), idx + 8)
        key = (start, end)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        text = "\n".join(lines[start:end])
        if text and text not in windows:
            windows.append(text[:1400])
        if len(windows) >= 8:
            break
    return windows


records = []
inspected = []
disasm_evidence = {}
binary_traits_by_path = {}
flag_candidates = []
notes_list = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")

if not binary_files:
    records.append({"type": "summary", "text": "Binary disassembly failed: missing required metadata.binary_files."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_binaries": [], "disassembly": {}, "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

if not _has_objdump():
    records.append({
        "type": "summary",
        "text": "objdump unavailable in this environment; binary disassembly skipped.",
    })
    records.append({
        "type": "output_context",
        "files_root": str(files_root),
        "inspected_binaries": [],
        "disassembly": {},
        "flag_candidates": [],
        "tool_status": "objdump_missing",
    })
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    raise SystemExit(0)

targets = _resolve_file_targets(files_root, binary_files, max_files=max_files, kind="binary")
for target in targets:
    relpath = target["display"]
    path = Path(target["path"])
    inspected.append(relpath)

    ftype = _file_type(path)
    if ("ELF" not in ftype) and ("Mach-O" not in ftype) and ("PE32" not in ftype):
        disasm_evidence[relpath] = {
            "file_type": ftype,
            "note": "Non-executable or unsupported format; skipped disassembly.",
        }
        continue

    # Intel syntax on x86 is easier for the LLM; fall back to default syntax
    # when -M is rejected (LLVM objdump, non-x86 ELF, etc.) or when --no-show-raw-insn
    # is unsupported on older binutils.
    raw_disasm, dis_err, dis_rc = _run(
        ["objdump", "-d", "--no-show-raw-insn", "-M", "intel", str(path)],
        timeout=25,
    )
    if dis_rc != 0 or not raw_disasm:
        raw_disasm, dis_err, dis_rc = _run(
            ["objdump", "-d", "--no-show-raw-insn", str(path)],
            timeout=25,
        )
    if dis_rc != 0 or not raw_disasm:
        # Drop --no-show-raw-insn as a final fallback (some objdump builds
        # alias the option differently); accept the extra bytes column.
        raw_disasm, dis_err, dis_rc = _run(
            ["objdump", "-d", str(path)],
            timeout=25,
        )
    if not raw_disasm:
        disasm_evidence[relpath] = {
            "file_type": ftype,
            "note": "objdump produced no output (possibly a stripped or packed binary).",
            "stderr_tail": dis_err[-300:],
        }
        continue

    funcs = _parse_disassembly(raw_disasm)
    rodata = _rodata(path)
    symbols = _symbol_table(path)
    xrefs = _string_xrefs(funcs, rodata)
    traits = _binary_traits(path, ftype, symbols)
    binary_traits_by_path[relpath] = traits

    # Flag tokens that live verbatim in .rodata are easy wins.
    for _addr, value in rodata:
        for m in flag_re.findall(value):
            if m not in flag_candidates:
                flag_candidates.append(m)

    keep = _entry_set(symbols, funcs, xrefs)

    used_chars = 0
    kept_funcs = []
    any_truncated = False
    # Greedy budget allocation: the first kept function (by ``_entry_set``
    # priority order — main, then xref-heavy, then mid-size non-noise)
    # gets to use as much of the per-binary budget as it needs, capped at
    # MAX_DISASM_CHARS_PER_BINARY.  Subsequent kept functions only run if
    # there is leftover budget.  This guarantees that when GNU objdump
    # emits ``.text`` as one giant block covering the whole code section
    # (stripped-binary case), it actually fits in the prompt instead of
    # being chopped to MAX_FUNC_BODY_CHARS just because some 5-line PLT
    # padding chunk also passed the noise filter.
    for name in keep:
        remaining = MAX_DISASM_CHARS_PER_BINARY - used_chars - 60
        if remaining <= 0:
            break
        raw_body = funcs.get(name, "")
        truncated = len(raw_body) > remaining
        any_truncated = any_truncated or truncated
        body = _condense_function(raw_body, budget=remaining)
        if not body:
            continue
        used_chars += len(body) + 60
        kept_funcs.append({
            "name": name,
            "size_lines": body.count("\n") + 1,
            "truncated": truncated,
            "xref_strings": xrefs.get(name, [])[:6],
            "disassembly": body,
        })

    rodata_excerpt = []
    used_rodata = 0
    for addr, value in rodata:
        if used_rodata >= MAX_RODATA_CHARS:
            break
        if len(value) < 4:
            continue
        rodata_excerpt.append({"address": "0x%x" % addr, "value": value[:160]})
        used_rodata += len(value) + 16

    disasm_evidence[relpath] = {
        "file_type": ftype,
        "binary_traits": traits,
        "function_count_total": len(funcs),
        "function_count_kept": len(kept_funcs),
        "symbol_table_present": bool(symbols),
        "disassembly_truncated": any_truncated,
        "functions": kept_funcs,
        "rodata": rodata_excerpt,
        "analysis_windows": _analysis_windows(raw_disasm, rodata),
    }
    notes_list.append(
        "Disassembled " + relpath + ": total funcs=" + str(len(funcs))
        + " kept=" + str(len(kept_funcs))
        + " rodata=" + str(len(rodata_excerpt))
        + " symbols=" + ("yes" if symbols else "stripped")
        + " arch=" + str(traits.get("arch"))
        + " go_like=" + str(traits.get("go_like")).lower() + "."
    )

if not inspected:
    records.append({"type": "summary", "text": "Binary disassembly failed: no requested binary files could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "binary_files": binary_files[:max_files], "inspected_binaries": [], "disassembly": {}, "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

records.append({
    "type": "summary",
    "text": (
        "Binary disassembly completed for " + str(len(inspected)) + " file(s): "
        + str(sum(len((d or {}).get("functions", [])) for d in disasm_evidence.values()))
        + " function(s) kept, " + str(len(flag_candidates)) + " flag candidate(s)."
    ),
})

for note in notes_list:
    records.append({"type": "note", "text": note})

records.append({
    "type": "finding",
    "finding_id": "finding-binary-disassembly",
    "title": "Binary disassembly evidence collected",
    "severity": "info",
    "description": (
        "Disassembled " + str(len(inspected))
        + " bundled binary artifact(s); see output_context['disassembly']"
        + " for per-function objdump excerpts."
    ),
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "binary_disassembly", "inspected": inspected},
})

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-binary-disassembly-flags",
        "title": "Flag-like token recovered from .rodata",
        "severity": "high",
        "description": "Recovered " + str(len(flag_candidates)) + " flag candidate(s) from .rodata.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "binary_disassembly", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_binaries": inspected,
    "disassembly": disasm_evidence,
    "binary_traits": binary_traits_by_path,
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Read the kept function bodies to recover the binary's per-step algorithm.",
        "Cross-reference rodata strings with the function that loads them to localize parsing logic.",
        "If no flag is in .rodata, run a script that mirrors the disassembled algorithm rather than guessing.",
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
        "max_files": request.metadata.get("max_files", 4),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
