"""LLM-driven solver code generation and execution agent.

This is the primary capability gap filler: instead of only asking the LLM
for "flag candidates" or "interesting paths", this agent asks the LLM to
write an executable solver script based on accumulated evidence, then runs
it inside the challenge container.
"""

from __future__ import annotations

import json
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

{technique_hints}

Return JSON matching the SolverCodeGuidance schema with your complete solver code \
in the solver_code field."""

_TECHNIQUE_HINTS = {
    "web": """\
WEB TECHNIQUE REFERENCE (from real CTF solutions):
- LFI: curl 'http://host/path?param=../../../flag.txt'
- SQLi: ' OR 1=1 -- , ' UNION SELECT flag FROM flags --
- SSTI: {{{{7*7}}}}, {{{{config}}}}, {{{{self.__class__.__mro__}}}}
- Multi-step: register → login → access protected endpoint → get flag
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


def _build_solver_user_prompt(
    task: Task,
    state: GlobalState,
) -> str:
    challenge_meta = state.metadata.get("challenge", {})

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
        "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
    }

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

    return json.dumps(evidence_snapshot, ensure_ascii=True, indent=2)


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
    supported_task_types = ("solve.generate_script",)
    routing_summary = (
        "LLM-driven solver that writes and executes custom scripts to solve the challenge. "
        "The most powerful agent — combines all evidence into an executable solution."
    )
    preferred_challenge_categories = ("crypto", "rev", "web", "forensics", "pwn", "misc")

    _MAX_RETRIES = 2

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.llm_client is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an LLM client; none is configured.",
                error="SolverAgent.llm_client is None",
            )
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an execution plane; none is configured.",
                error="SolverAgent.execution_plane is None",
            )

        challenge_meta = state.metadata.get("challenge", {})
        category = str(challenge_meta.get("category") or "misc").lower()
        attempt_num = int(task.input_context.get("attempt_number", 1))
        timeout_s = int(task.input_context.get("solver_timeout_s", 30))

        worker_notes: list[str] = []

        guidance = self.generate_structured_output(
            system_prompt=_build_solver_system_prompt(category, timeout=timeout_s),
            user_prompt=_build_solver_user_prompt(task, state),
            schema=SolverCodeGuidance,
            temperature=0.3,
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
            limit=12,
        )

        new_tasks = [
            build_flag_validation_task(candidate, source="solver_execution")
            for candidate in flag_candidates
        ]

        # Schedule a retry if solver failed and we haven't exhausted attempts
        returncode = output_context.get("returncode", -1)
        if (
            not flag_candidates
            and guidance.should_retry_on_failure
            and attempt_num < self._MAX_RETRIES
        ):
            stderr = str(output_context.get("stderr", ""))[:500]
            stdout = str(output_context.get("stdout", ""))[:500]
            retry_task = Task(
                title=f"Solver retry (attempt {attempt_num + 1})",
                description="Retry solver generation with previous failure context.",
                task_type="solve.generate_script",
                priority=97,
                input_context={
                    "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                    "attempt_number": attempt_num + 1,
                    "solver_timeout_s": timeout_s,
                    "previous_attempts": (task.input_context.get("previous_attempts") or []) + [
                        {
                            "attempt": attempt_num,
                            "solver_code_preview": guidance.solver_code[:500],
                            "returncode": returncode,
                            "stderr": stderr,
                            "stdout": stdout,
                            "error_summary": f"Attempt {attempt_num} failed: exit code {returncode}",
                        }
                    ],
                },
                dedupe_key=f"solver-retry:{task.task_id}:attempt-{attempt_num + 1}",
                metadata={"planned_by": "solver-agent", "retry_of": task.task_id},
            )
            new_tasks.append(retry_task)
            worker_notes.append(f"Solver attempt {attempt_num} produced no flags; scheduling retry.")

        output_context["flag_candidates"] = flag_candidates
        output_context["solver_code_preview"] = guidance.solver_code[:500]
        output_context["solver_reasoning"] = guidance.reasoning
        output_context["solver_confidence"] = guidance.confidence
        if guidance.reasoning:
            output_context["llm_summary"] = guidance.summary

        success = bool(flag_candidates) or returncode == 0
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
