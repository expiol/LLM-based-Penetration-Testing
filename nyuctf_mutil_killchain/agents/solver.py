"""LLM-driven solver code generation and execution agent.

This is the primary capability gap filler: instead of only asking the LLM
for "flag candidates" or "interesting paths", this agent asks the LLM to
write an executable solver script based on accumulated evidence, then runs
it inside the challenge container.
"""

from __future__ import annotations

import json
import re
from typing import Any

from nyuctf_mutil_killchain.agents.base import (
    WorkerAgent,
    build_flag_validation_task,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import SolverCodeGuidance
from nyuctf_mutil_killchain.prompts import get_prompts
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


_SOLVER_SYSTEM_PROMPT_TEMPLATE = """\
You are an expert CTF solver. Your job is to write a complete, executable \
{language} script that solves the given CTF challenge and prints the flag to stdout.

Challenge category: {category}

{category_strategy}

CRITICAL RULES:
- The script runs inside a Docker container at /home/ctfplayer/ctf_files
- Challenge files are already present in that directory
- Print ONLY the flag to stdout (format: flag{{...}} or similar)
- The script must be self-contained — do not import from custom challenge modules \
unless they are bundled files you've analyzed
- Use standard library + common packages (requests, pwntools, pycryptodome, gmpy2, \
z3-solver, pyshark, PIL, binascii, struct, etc.)
- If the challenge has a remote service, connect to the hostname and port from the \
evidence (NOT localhost unless explicitly stated)
- Maximum runtime: {timeout}s
- Do NOT guess or hallucinate the flag — compute it from the evidence
- IMPORTANT: If challenge_source_files are provided in the evidence, study them \
carefully to understand the exact algorithm before writing your solver. Do NOT \
brute-force when the algorithm can be reversed analytically
- Read any binary files (ciphertext, data blobs) with open(path, 'rb')

{technique_hints}

Return JSON matching the SolverCodeGuidance schema with your complete solver code \
in the solver_code field."""

_TECHNIQUE_HINTS = {
    "web": """\
WEB TECHNIQUE REFERENCE (from real CTF solutions):
- LFI: curl 'http://host/path?param=../../../flag.txt'
- SQLi (string context): ' OR 1=1 -- , ' UNION SELECT flag FROM flags --
- SQLi (identifier / quoting context): if errors show delimited names (e.g. \
backticks, brackets), the app may splice parameters inside identifiers — test \
breakout using that DB's identifier rules and valid comment tokens (#, --) \
where SQL comments apply; classic quote payloads may be escaped while other \
characters are not
- Escaping vs context: map whether each parameter is used inside string literals, \
identifiers, or ORDER BY — the same sanitizer (e.g. addslashes-style) often \
misses delimiter-breaking characters
- SSTI: {{{{7*7}}}}, {{{{config}}}}, {{{{self.__class__.__mro__}}}}
- Multi-step: register → login → access protected endpoint → get flag
- Client-side submit handlers: fetch HTML-linked *.js (login, auth, bundle) and \
mirror any hash/base64/HMAC transforms so POST bodies match what the browser sends
- Cookie manipulation: decode JWT/base64 cookies, forge admin role
- Path traversal: ../, %2e%2e/, double encoding
Use the `requests` library for HTTP interaction.""",

    "crypto": """\
CRYPTO TECHNIQUE REFERENCE (from real CTF solutions):
- RSA weak key: factor n via factordb.com API or yafu, then d = inverse(e, phi)
- XOR: ciphertext ^ known_plaintext_prefix → key fragment → full key
- AES-CBC: known key+IV → AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
- Hash collision: MD5/SHA brute-force with itertools.product
- LFSR: reconstruct state from known output bits
- Modular arithmetic: use gmpy2.invert, pow(base, exp, mod)
Use pycryptodome (from Crypto.Cipher import AES), gmpy2, sympy as needed.""",

    "rev": """\
REVERSE ENGINEERING TECHNIQUE REFERENCE (from real CTF solutions):
- XOR key extraction: identify pkey[] array, XOR with known flag prefix
- Transform chains: reverse each step (shift, substitute, permute)
- Checker bypass: extract expected output, solve for input
- Binary strings: use subprocess to run 'strings' on ELF files
- Disassembly: subprocess.run(['objdump', '-d', binary]) to find constants
- For Python bytecode: dis module, uncompyle6
Write an inverse function and apply it to the encoded data.""",

    "pwn": """\
PWN TECHNIQUE REFERENCE (from real CTF solutions):
- Buffer overflow: from pwn import *; p = remote(host, port); p.sendline(payload)
- Address calculation: use provided binary to find offsets
- Format string: send %p.%p.%p to leak stack, %n to write
- ROP: from pwn import ROP; rop = ROP(elf); rop.call('system', ['/bin/sh'])
- ret2libc: leak libc base via GOT, compute system() address
Use pwntools (from pwn import *) for binary exploitation.""",

    "forensics": """\
FORENSICS TECHNIQUE REFERENCE (from real CTF solutions):
- PCAP: import pyshark; cap = FileCapture('file.pcap'); filter DNS/HTTP
- Steganography: from PIL import Image → check LSB, check EOF appended data
- Archives: subprocess.run(['binwalk', '-e', file]) to extract embedded files
- Disk images: subprocess.run(['fdisk', '-l', img]) then mount + search
- Git history: subprocess.run(['git', 'log', '--all', '-p']) → grep for flag
- Base64 chains: repeatedly b64decode until readable
Use pyshark, PIL, subprocess with forensic tools.""",

    "misc": """\
MISC TECHNIQUE REFERENCE (from real CTF solutions):
- Encoding chains: base64 → hex → ROT13 → morse, try all combinations
- Python jail escape: __builtins__, __import__('os').system('cat flag*')
- Programming puzzles: parse input, implement algorithm, compute answer
- Esoteric languages: brainfuck, whitespace → use interpreter libraries
- File inspection: check file headers, look for appended data, alternate streams
Be creative and try multiple approaches.""",
}


def _build_solver_system_prompt(
    category: str,
    language: str = "Python",
    timeout: int = 30,
) -> str:
    prompts = get_prompts(category)
    technique_hints = _TECHNIQUE_HINTS.get(category, _TECHNIQUE_HINTS["misc"])
    return _SOLVER_SYSTEM_PROMPT_TEMPLATE.format(
        language=language,
        category=category,
        category_strategy=prompts.exploit_strategy,
        timeout=timeout,
        technique_hints=technique_hints,
    )


_SOURCE_EXTENSIONS = frozenset({
    ".py", ".js", ".rb", ".pl", ".sh", ".c", ".cpp", ".h", ".java",
    ".php", ".go", ".rs", ".sage", ".txt", ".md", ".yml", ".yaml",
    ".json", ".xml", ".html", ".css", ".sql", ".lua", ".r",
})
_MAX_SOURCE_CHARS_PER_FILE = 6000
_MAX_TOTAL_SOURCE_CHARS = 18000


def _collect_challenge_source_files(
    state: GlobalState,
    files_root: str,
) -> list[dict[str, str]]:
    """Collect actual content of bundled challenge source files from state.

    This gives the solver LLM direct access to the challenge code so it can
    understand the algorithm instead of guessing blindly.  It searches for
    source content in three places:
      1. Findings metadata (source_snippet from computation_analysis/source_review)
      2. Evidence stdout_preview (from solver retries or runtime_probe)
      3. Task output_context (source_snippets, file_previews)
    """
    challenge_meta = state.metadata.get("challenge", {})
    filenames = challenge_meta.get("files", [])
    if not filenames:
        return []

    collected: list[dict[str, str]] = []
    total_chars = 0
    for filename in filenames:
        ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        if ext not in _SOURCE_EXTENSIONS:
            collected.append({"filename": filename, "note": f"binary file (skipped content, available at {files_root}/{filename})"})
            continue

        found = False

        for finding in state.findings.values():
            snippet = finding.metadata.get("source_snippet") or ""
            if snippet and filename in (finding.description or "") and len(snippet) > 100:
                budget = min(_MAX_SOURCE_CHARS_PER_FILE, _MAX_TOTAL_SOURCE_CHARS - total_chars)
                if budget > 200:
                    collected.append({"filename": filename, "content": snippet[:budget]})
                    total_chars += len(snippet[:budget])
                    found = True
                    break
            refs = finding.evidence_refs or []
            if filename in refs and snippet and len(snippet) > 100:
                budget = min(_MAX_SOURCE_CHARS_PER_FILE, _MAX_TOTAL_SOURCE_CHARS - total_chars)
                if budget > 200:
                    collected.append({"filename": filename, "content": snippet[:budget]})
                    total_chars += len(snippet[:budget])
                    found = True
                    break

        if not found:
            for ev in state.evidence.values():
                result = ev.result or {}
                stdout_preview = result.get("stdout_preview") or ev.extracted.get("stdout_preview") or ""
                if filename in stdout_preview and len(stdout_preview) > 200:
                    budget = min(_MAX_SOURCE_CHARS_PER_FILE, _MAX_TOTAL_SOURCE_CHARS - total_chars)
                    if budget > 200:
                        collected.append({"filename": filename, "content": stdout_preview[:budget]})
                        total_chars += len(stdout_preview[:budget])
                        found = True
                        break

        if not found:
            collected.append({"filename": filename, "note": f"source file at {files_root}/{filename} (read it in your script with open())"})

        if total_chars >= _MAX_TOTAL_SOURCE_CHARS:
            break

    return collected


def _build_solver_user_prompt(
    task: Task,
    state: GlobalState,
) -> str:
    challenge_meta = state.metadata.get("challenge", {})
    files_root = task.input_context.get("files_root", "/home/ctfplayer/ctf_files")

    evidence_snapshot: dict[str, Any] = {
        "objective": state.objective,
        "challenge": {
            "name": challenge_meta.get("name"),
            "category": challenge_meta.get("category"),
            "flag_format": challenge_meta.get("flag_format"),
            "description": str(state.objective or "")[:500],
            "files": challenge_meta.get("files", []),
            "server_name": challenge_meta.get("server_name"),
            "port": challenge_meta.get("port"),
        },
        "files_root": files_root,
    }

    # Inject actual challenge source file content
    challenge_sources = _collect_challenge_source_files(state, files_root)
    if challenge_sources:
        evidence_snapshot["challenge_source_files"] = challenge_sources

    # Source code snippets from findings
    source_snippets: list[dict[str, str]] = []
    for finding in state.findings.values():
        meta = finding.metadata
        if meta.get("source") in {"source_review", "computation_analysis", "runtime_probe"}:
            for key in ("stdout_preview", "source_snippet", "function_inventory", "interesting_routes"):
                if meta.get(key):
                    source_snippets.append({"source": str(finding.title), key: str(meta[key])[:600]})
        if meta.get("runtime_outputs"):
            for output in meta["runtime_outputs"][:3]:
                source_snippets.append({"runtime_output": output})
        if meta.get("recovered_plaintexts"):
            source_snippets.append({"recovered_plaintexts": meta["recovered_plaintexts"][:3]})

    evidence_snapshot["source_evidence"] = source_snippets[:10]

    evidence_snapshot["assets"] = [
        {
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "base_url": asset.base_url,
            "services": [
                {"port": s.port, "name": s.name, "product": s.product}
                for s in asset.services
            ],
        }
        for asset in state.assets.values()
    ]

    evidence_snapshot["credentials"] = [
        {
            "credential_id": cred.credential_id,
            "username": cred.username,
            "credential_type": cred.credential_type,
            "secret_value": cred.metadata.get("secret_value", ""),
        }
        for cred in list(state.credentials.values())[:8]
    ]

    evidence_snapshot["key_findings"] = [
        {
            "title": f.title,
            "severity": f.severity,
            "description": (f.description or "")[:300],
            "evidence_refs": f.evidence_refs[:5],
        }
        for f in list(state.findings.values())[-12:]
    ]

    # Include file content hints from completed tasks
    file_contents: list[dict[str, str]] = []
    for task_entry in state.task_chain.tasks[-10:]:
        ctx = task_entry.output_context or {}
        for key in ("source_snippets", "file_previews", "interesting_strings", "blob_candidates"):
            if ctx.get(key):
                file_contents.append({key: str(ctx[key])[:800]})
    evidence_snapshot["file_contents"] = file_contents[:8]

    # Previous solver attempts (for retry)
    prev_attempts = task.input_context.get("previous_attempts", [])
    if prev_attempts:
        evidence_snapshot["previous_solver_attempts"] = prev_attempts[-3:]

        # Surface near-miss diagnostics prominently so the LLM knows its
        # previous approach was close but needs refinement.
        near_miss_diags: list[str] = []
        for attempt in prev_attempts[-3:]:
            nm = attempt.get("near_miss_candidates") or []
            diag = attempt.get("error_diagnosis") or ""
            if nm:
                near_miss_diags.append(
                    f"Attempt {attempt.get('attempt', '?')}: output contained near-miss "
                    f"flag pattern(s) {nm} — the decryption produced flag-shaped output "
                    f"but with non-printable/garbage bytes, meaning the key or transform "
                    f"was partially wrong. You MUST use a different strategy for the "
                    f"bytes/positions that produced garbage."
                )
            elif diag:
                near_miss_diags.append(diag)
        if near_miss_diags:
            evidence_snapshot["CRITICAL_RETRY_GUIDANCE"] = near_miss_diags

    return json.dumps(evidence_snapshot, ensure_ascii=True, indent=2)


_NEAR_MISS_CLEAN_RE = re.compile(r"[^\x20-\x7e]")


def _clean_near_miss_candidates(near_miss: list[str]) -> list[str]:
    """Strip non-printable characters from near-miss flag strings.

    Returns cleaned candidates that still look like plausible flags
    (prefix + braces + body of at least 4 printable chars).
    """
    cleaned: list[str] = []
    for raw in near_miss:
        prefix, _, rest = raw.partition("{")
        if not rest or not rest.endswith("}"):
            continue
        body = rest[:-1]
        clean_body = _NEAR_MISS_CLEAN_RE.sub("", body)
        if len(clean_body) >= 4 and prefix.isalnum():
            candidate = f"{prefix}{{{clean_body}}}"
            if candidate not in cleaned:
                cleaned.append(candidate)
    return cleaned


class SolverAgent(WorkerAgent):
    """Asks the LLM to write a complete solver script, then executes it.

    This is the primary LLM utilization agent — it treats the LLM as a
    code-writing solver, not just an advisor. The agent:
    1. Feeds all accumulated evidence to the LLM
    2. Asks it to write an executable solver script
    3. Runs the script in the container
    4. Captures flag candidates from output
    5. On failure, can retry with error context
    """

    name = "solver-agent"
    supported_task_types = ("solve.generate_script", "post_exploit.loot", "post_exploit.lateral_move")
    routing_summary = (
        "LLM-driven solver that writes and executes custom scripts to solve the challenge. "
        "The most powerful agent — combines all evidence into an executable solution."
    )
    preferred_challenge_categories = ("crypto", "rev", "web", "forensics", "pwn", "misc")

    _MAX_RETRIES = 4
    _CATEGORY_TIMEOUT: dict[str, int] = {
        "crypto": 120,
        "rev": 90,
        "pwn": 60,
        "forensics": 60,
        "web": 45,
        "misc": 60,
    }

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.llm_client is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an LLM client; none is configured.",
                error="SolverAgent.llm_client is None",
                retryable=False,
            )
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an execution plane; none is configured.",
                error="SolverAgent.execution_plane is None",
                retryable=False,
            )

        challenge_meta = state.metadata.get("challenge", {})
        category = str(challenge_meta.get("category") or "misc").lower()
        attempt_num = int(task.input_context.get("attempt_number", 1))
        default_timeout = self._CATEGORY_TIMEOUT.get(category, 60)
        timeout_s = int(task.input_context.get("solver_timeout_s", default_timeout))

        worker_notes: list[str] = []

        try:
            guidance = self.generate_structured_output(
                system_prompt=_build_solver_system_prompt(category, timeout=timeout_s),
                user_prompt=_build_solver_user_prompt(task, state),
                schema=SolverCodeGuidance,
                temperature=0.3,
            )
        except Exception as exc:
            error_msg = f"{type(exc).__name__}: {exc}"
            worker_notes.append(f"LLM code generation failed: {error_msg}")

            retry_task = None
            if attempt_num < self._MAX_RETRIES:
                retry_task = Task(
                    title=f"Solver retry (attempt {attempt_num + 1})",
                    description="Retry solver generation after LLM failure.",
                    task_type="solve.generate_script",
                    priority=97,
                    input_context={
                        "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                        "attempt_number": attempt_num + 1,
                        "previous_attempts": (task.input_context.get("previous_attempts") or []) + [
                            {
                                "attempt": attempt_num,
                                "error_summary": error_msg,
                                "error_diagnosis": (
                                    f"Attempt {attempt_num}: LLM call failed with {type(exc).__name__}. "
                                    "The LLM may have timed out or returned malformed JSON. "
                                    "Generate the solver code again with a fresh approach."
                                ),
                            }
                        ],
                    },
                    dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt_num + 1}",
                    metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
                )

            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"LLM code generation failed: {error_msg}",
                error=error_msg,
                notes=worker_notes,
                new_tasks=[retry_task] if retry_task else [],
                retryable=False,
            )

        if guidance is None or not guidance.solver_code.strip():
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="LLM failed to generate solver code.",
                error="No solver code was produced by the LLM.",
                notes=worker_notes,
            )

        worker_notes.append(f"LLM generated {guidance.solver_language} solver (confidence: {guidance.confidence:.1%}).")
        if guidance.reasoning:
            worker_notes.append(f"Reasoning: {guidance.reasoning[:300]}")

        request = ToolExecutionRequest(
            tool_name="solver_execution",
            parser_name="jsonl_signals",
            timeout_s=timeout_s + 10,
            metadata={
                "solver_code": guidance.solver_code,
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "timeout_s": timeout_s,
                "flag_format": challenge_meta.get("flag_format"),
                "solver_language": guidance.solver_language,
            },
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver execution failed.",
                error=str(exc),
                notes=worker_notes,
            )

        output_context = dict(bundle.parsed.output_context)
        flag_candidates = merge_unique_strings(
            output_context.get("flag_candidates") or [],
            guidance.grounded_flag_candidates,
            limit=6,
        )

        new_tasks = [
            build_flag_validation_task(candidate, source="solver_execution")
            for candidate in flag_candidates
        ]

        # Auto-validate cleaned near-miss candidates as a long-shot attempt
        returncode = output_context.get("returncode", -1)
        near_miss = output_context.get("near_miss_candidates") or []
        if not flag_candidates and near_miss:
            cleaned = _clean_near_miss_candidates(near_miss)
            for candidate in cleaned[:3]:
                if candidate not in flag_candidates:
                    new_tasks.append(
                        build_flag_validation_task(candidate, source="solver_near_miss_cleaned")
                    )
            if cleaned:
                worker_notes.append(
                    f"Auto-cleaned {len(cleaned)} near-miss candidate(s) for validation: {cleaned[:3]}"
                )
        if (
            not flag_candidates
            and guidance.should_retry_on_failure
            and attempt_num < self._MAX_RETRIES
        ):
            stderr = str(output_context.get("stderr", ""))[:1500]
            stdout = str(output_context.get("stdout", ""))[:1500]

            error_diagnosis = f"Attempt {attempt_num} failed: exit code {returncode}"
            if near_miss:
                error_diagnosis = (
                    f"Attempt {attempt_num}: solver output contained flag-like pattern(s) "
                    f"with non-printable characters ({near_miss[:3]}), suggesting the "
                    f"decryption/decode approach was partially correct but key recovery "
                    f"or transform was incomplete. Refine the algorithm — do NOT repeat "
                    f"the same approach."
                )
            elif returncode == 0 and not stdout.strip():
                error_diagnosis = (
                    f"Attempt {attempt_num}: script exited 0 but produced no output. "
                    f"Ensure the script prints the flag to stdout."
                )
            elif returncode != 0:
                error_diagnosis = (
                    f"Attempt {attempt_num}: script crashed with exit code {returncode}. "
                    f"Fix the runtime error and try a different approach."
                )
            else:
                error_diagnosis = (
                    f"Attempt {attempt_num}: script exited 0 but no valid flag found in output. "
                    f"The output may contain garbled data — review the algorithm."
                )

            retry_timeout = timeout_s + 30 if near_miss else timeout_s
            retry_task = Task(
                title=f"Solver retry (attempt {attempt_num + 1})",
                description="Retry solver generation with previous failure context.",
                task_type="solve.generate_script",
                priority=97,
                input_context={
                    "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                    "attempt_number": attempt_num + 1,
                    "solver_timeout_s": retry_timeout,
                    "previous_attempts": (task.input_context.get("previous_attempts") or []) + [
                        {
                            "attempt": attempt_num,
                            "solver_code_preview": guidance.solver_code[:500],
                            "returncode": returncode,
                            "stderr": stderr,
                            "stdout": stdout,
                            "near_miss_candidates": near_miss[:3],
                            "error_summary": f"Attempt {attempt_num} failed: exit code {returncode}",
                            "error_diagnosis": error_diagnosis,
                        }
                    ],
                },
                dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt_num + 1}",
                metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
            )
            new_tasks.append(retry_task)
            worker_notes.append(f"Solver attempt {attempt_num} produced no flags; scheduling retry.")
            if near_miss:
                worker_notes.append(f"Near-miss flag patterns detected: {near_miss[:3]}")

        output_context["flag_candidates"] = flag_candidates
        output_context["solver_code_preview"] = guidance.solver_code[:500]
        output_context["solver_reasoning"] = guidance.reasoning
        output_context["solver_confidence"] = guidance.confidence
        if guidance.reasoning:
            output_context["llm_summary"] = guidance.summary

        success = bool(flag_candidates)
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=success,
            summary=bundle.parsed.summary,
            output_context=output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + bundle.parsed.notes + [
                f"{self.name} executed LLM-generated solver (attempt {attempt_num})."
            ],
        )
