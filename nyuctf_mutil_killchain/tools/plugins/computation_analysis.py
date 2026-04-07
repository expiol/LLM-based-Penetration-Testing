"""Dynamic computation-heavy source analysis tool."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.tools.core import ToolExecutionRequest

TOOL_NAME = "computation_analysis"

SCRIPT = r"""
import ast
import inspect
import json
import re
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
source_files = payload.get("source_files") or []
max_files = int(payload.get("max_files", 8))
flag_format = str(payload.get("flag_format") or "")

records = []
notes_list = []
inspected = []
bitstring_constants = {}
function_inventory = {}
recovered_plaintexts = []
flag_candidates = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
bitstring_re = re.compile(r"^[01]{24,}$")
preferred_names = (
    "decode",
    "decrypt",
    "recover",
    "inverse",
    "solve",
    "unscramble",
    "encode",
    "encrypt",
    "transform",
    "check",
)


def unique(items):
    seen = set()
    out = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def printable_ratio(text):
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch == "\n" or 32 <= ord(ch) <= 126)
    return printable / len(text)


def build_basis(columns):
    basis = {}
    for index, vector in enumerate(columns):
        value = int(vector)
        combination = 1 << index
        while value:
            lead = value.bit_length() - 1
            if lead not in basis:
                basis[lead] = (value, combination)
                break
            value ^= basis[lead][0]
            combination ^= basis[lead][1]
    return basis


def solve_basis(basis, target_value):
    value = int(target_value)
    combination = 0
    while value:
        lead = value.bit_length() - 1
        if lead not in basis:
            return None
        value ^= basis[lead][0]
        combination ^= basis[lead][1]
    return combination


def candidate_lengths_for_target(target_bits):
    lengths = []
    if len(target_bits) % 8 == 0:
        lengths.append(len(target_bits) // 8)
    lengths.extend(range(1, min(64, len(target_bits)) + 1))
    return unique(lengths)


def collect_string_constants(module):
    strings = []
    for node in ast.walk(module):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.append(node.value)
    return strings


def candidate_functions(namespace):
    ranked = []
    for name, value in namespace.items():
        if name.startswith("_") or not inspect.isfunction(value):
            continue
        try:
            signature = inspect.signature(value)
        except (TypeError, ValueError):
            continue
        positional = [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        required = [parameter for parameter in positional if parameter.default is inspect.Parameter.empty]
        if len(required) != 1 or len(positional) != 1:
            continue
        priority = preferred_names.index(name) if name in preferred_names else len(preferred_names)
        ranked.append((priority, name, value))
    ranked.sort(key=lambda item: (item[0], item[1]))
    return [(name, func) for _, name, func in ranked]


def attempt_linear_bitstring_inverse(func, target_bits):
    if not target_bits or len(target_bits) > 4096 or not bitstring_re.match(target_bits):
        return None

    for bit_width in (7, 8):
        for plain_len in candidate_lengths_for_target(target_bits):
            baseline_input = "\x00" * plain_len
            try:
                baseline = func(baseline_input)
            except Exception:
                continue

            if (
                not isinstance(baseline, str)
                or len(baseline) != len(target_bits)
                or set(baseline) - {"0", "1"}
            ):
                continue

            baseline_value = int(baseline, 2)
            columns = []
            valid = True
            for position in range(plain_len):
                for bit in range(bit_width):
                    probe_chars = ["\x00"] * plain_len
                    probe_chars[position] = chr(1 << bit)
                    try:
                        observed = func("".join(probe_chars))
                    except Exception:
                        valid = False
                        break

                    if (
                        not isinstance(observed, str)
                        or len(observed) != len(target_bits)
                        or set(observed) - {"0", "1"}
                    ):
                        valid = False
                        break
                    columns.append(int(observed, 2) ^ baseline_value)
                if not valid:
                    break

            if not valid:
                continue

            basis = build_basis(columns)
            solution_bits = solve_basis(basis, int(target_bits, 2) ^ baseline_value)
            if solution_bits is None:
                continue

            chars = []
            for position in range(plain_len):
                value = 0
                for bit in range(bit_width):
                    column_index = position * bit_width + bit
                    if (solution_bits >> column_index) & 1:
                        value |= 1 << bit
                chars.append(chr(value))
            candidate = "".join(chars)

            try:
                if func(candidate) != target_bits:
                    continue
            except Exception:
                continue

            if printable_ratio(candidate) < 0.8 and not flag_re.findall(candidate):
                continue

            return {
                "candidate_plaintext": candidate,
                "bit_width": bit_width,
                "plain_len": plain_len,
            }
    return None


if not files_root.exists():
    records.append({"type": "summary", "text": f"Computation analysis skipped: {files_root} does not exist."})
    records.append({"type": "note", "text": f"Challenge files root not found: {files_root}"})
else:
    notes_list.append("Dynamic computation analysis executes bundled Python sources with container-level privileges.")
    if flag_format:
        notes_list.append(f"Expected flag format hint: {flag_format}")

    for relpath in source_files[:max_files]:
        path = files_root / relpath
        if not path.is_file():
            continue
        if path.suffix.lower() != ".py":
            continue

        try:
            source_text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            notes_list.append(f"Unable to read {relpath}: {exc}")
            continue

        inspected.append(relpath)
        # Store a source preview so downstream agents (e.g. solver) can see the code
        preview_key = f"source_preview:{relpath}"
        if preview_key not in bitstring_constants:
            records.append({
                "type": "finding",
                "finding_id": f"finding-source-preview-{relpath.replace('/', '_').replace('.', '_')}",
                "title": f"Source preview: {relpath}",
                "severity": "info",
                "description": f"Captured source preview of {relpath} ({len(source_text)} chars).",
                "asset_refs": ["challenge-files"],
                "evidence_refs": [relpath],
                "metadata": {
                    "source": "computation_analysis",
                    "source_snippet": source_text[:4000],
                },
            })
        try:
            module = ast.parse(source_text, filename=relpath)
        except SyntaxError as exc:
            notes_list.append(f"Syntax error in {relpath}: {exc}")
            continue

        string_constants = collect_string_constants(module)
        for flag in flag_re.findall(source_text):
            if flag not in flag_candidates:
                flag_candidates.append(flag)

        bit_candidates = unique([
            value.strip()
            for value in string_constants
            if isinstance(value, str) and bitstring_re.match(value.strip())
        ])
        if bit_candidates:
            bitstring_constants[relpath] = bit_candidates[:8]

        namespace = {"__name__": "_analysis_"}
        try:
            exec(compile(source_text, relpath, "exec"), namespace, namespace)
        except Exception as exc:
            notes_list.append(f"Execution failed for {relpath}: {type(exc).__name__}: {exc}")
            continue

        functions = candidate_functions(namespace)
        function_inventory[relpath] = [name for name, _ in functions]

        for target_bits in bit_candidates[:4]:
            for function_name, function in functions:
                result = attempt_linear_bitstring_inverse(function, target_bits)
                if result is None:
                    continue

                entry = {
                    "source_file": relpath,
                    "function_name": function_name,
                    "bit_width": result["bit_width"],
                    "plain_len": result["plain_len"],
                    "candidate_plaintext": result["candidate_plaintext"],
                }
                recovered_plaintexts.append(entry)
                for flag in flag_re.findall(result["candidate_plaintext"]):
                    if flag not in flag_candidates:
                        flag_candidates.append(flag)
                break

records.extend({"type": "note", "text": note} for note in notes_list)
records.append({
    "type": "summary",
    "text": (
        f"Computation analysis completed for {len(inspected)} file(s): "
        f"{len(recovered_plaintexts)} plaintext candidate(s), {len(flag_candidates)} flag candidate(s)."
    ),
})
records.append({
    "type": "finding",
    "finding_id": "finding-computation-analysis",
    "title": "Computation-heavy source artifacts analyzed",
    "severity": "info",
    "description": f"Executed dynamic computation analysis for {len(inspected)} Python source artifact(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {
        "source": "computation_analysis",
        "inspected": inspected,
        "function_inventory": function_inventory,
    },
})

if recovered_plaintexts:
    records.append({
        "type": "finding",
        "finding_id": "finding-computation-recovered-plaintext",
        "title": "Dynamic analysis recovered plaintext candidate",
        "severity": "high" if flag_candidates else "medium",
        "description": f"Recovered {len(recovered_plaintexts)} plaintext candidate(s) from computation-heavy source analysis.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": [entry["source_file"] for entry in recovered_plaintexts[:5]],
        "metadata": {
            "source": "computation_analysis",
            "recovered_plaintexts": recovered_plaintexts[:5],
        },
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-computation-flag-candidates",
        "title": "Flag candidate recovered from dynamic computation analysis",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from executed source artifacts.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {
            "source": "computation_analysis",
            "flag_candidates": flag_candidates[:10],
        },
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_sources": inspected,
    "function_inventory": function_inventory,
    "bitstring_constants": bitstring_constants,
    "recovered_plaintexts": recovered_plaintexts[:10],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Review recovered plaintext candidates against challenge context.",
        "Validate any flag-like token before submission.",
        "Escalate to a manual reversing workflow if no candidate was recovered.",
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
