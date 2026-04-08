"""Category-specific prompt registry for CTF challenge solving.

Centralizes all LLM prompt templates so that planners, routers, and worker
agents receive guidance tuned for the challenge category (web, rev, crypto,
forensics, pwn, misc) instead of generic one-size-fits-all instructions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CategoryPrompts:
    """Prompt bundle for one CTF category."""

    category: str
    objective_hint: str
    planner_system: str
    planner_focus: str
    worker_system_prefix: str
    analysis_strategy: str
    exploit_strategy: str
    flag_recovery_hints: list[str] = field(default_factory=list)
    solver_technique_examples: list[str] = field(default_factory=list)


_REGISTRY: dict[str, CategoryPrompts] = {}


def _register(prompts: CategoryPrompts) -> None:
    _REGISTRY[prompts.category] = prompts


# ---------------------------------------------------------------------------
# Web
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="web",
    objective_hint=(
        "Enumerate the reachable web surface, discover routes and forms, "
        "test for injection vulnerabilities (SQLi, XSS, SSTI, SSRF), "
        "check cookies and session handling, attempt credential reuse, "
        "and inspect any bundled source code for hardcoded secrets or hidden routes."
    ),
    planner_system=(
        "You are planning a web CTF challenge. Web challenges typically involve "
        "exploiting server-side or client-side vulnerabilities in a web application. "
        "Common attack vectors include SQL injection, command injection, SSTI, SSRF, "
        "path traversal, authentication bypass, cookie manipulation, and source code leaks."
    ),
    planner_focus=(
        "Prioritize: 1) Source code review for routes, secrets, and SQL queries, "
        "2) Web surface enumeration and form discovery, "
        "3) Static assets linked from pages (JS/CSS) that alter requests before submit, "
        "4) Credential harvesting from bundled files, "
        "5) Targeted injection testing on discovered forms/endpoints, "
        "6) Cookie/session manipulation and privilege escalation."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a web CTF challenge. "
        "Focus on identifying injectable parameters, hidden routes, authentication "
        "bypass opportunities, and server-side template injection points. "
        "Treat linked client scripts as part of the attack surface when they alter "
        "submitted fields (hashing, encoding, tokens). "
    ),
    analysis_strategy=(
        "For web challenges: inspect source for route definitions, SQL queries, "
        "template rendering calls, and hardcoded credentials. Check for common "
        "misconfigurations: debug mode, default credentials, exposed admin panels, "
        "directory listing, .git exposure. Identify all user-controllable inputs. "
        "When pages reference local scripts, review them for submit-time hashing, "
        "encoding, or signing so automated requests match browser behavior."
    ),
    exploit_strategy=(
        "Attempt grounded exploitation based on discovered evidence: "
        "SQLi on identified query parameters (consider both string and identifier "
        "contexts suggested by error messages or response shape), SSTI on template endpoints, "
        "path traversal on file-serving routes, credential reuse from harvested secrets, "
        "and cookie manipulation for privilege escalation."
    ),
    flag_recovery_hints=[
        "Check response bodies for flag patterns after successful injection",
        "Try accessing /flag, /admin, /api/flag endpoints with discovered credentials",
        "Look for flag in database tables via SQLi",
        "Check server-side template output for leaked secrets",
        "If credentials from the server fail on login, verify the page's JavaScript "
        "does not transform the password or token before POST",
    ],
    solver_technique_examples=[
        "# LFI: requests.get(f'{base}/page?file=../../../flag.txt').text",
        "# SQLi: requests.post(url, data={'user': \"' OR 1=1 --\", 'pass': 'x'})",
        "# Match browser POST: js = requests.get(f'{base}/static/login.js').text; "
        "# then apply same hash/b64 as submit handler before s.post(...)",
        "# SSTI: requests.get(f'{base}/render?name={{{{config}}}}')",
        "# Multi-step: s=requests.Session(); s.post(url+'/register',...); s.post(url+'/login',...); s.get(url+'/flag')",
        "# IDOR: requests.get(f'{base}/api/users/1/profile', cookies=session_cookie)",
    ],
))

# ---------------------------------------------------------------------------
# Reverse Engineering
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="rev",
    objective_hint=(
        "Inspect the bundled challenge files first, identify transform chains "
        "(XOR, shift, substitute, custom ciphers), extract hardcoded constants "
        "and encoded strings, write an inverse function when possible, "
        "and execute scripts to capture intermediate or final output."
    ),
    planner_system=(
        "You are planning a reverse engineering CTF challenge. These challenges "
        "require understanding compiled binaries or obfuscated scripts to recover "
        "the flag. The flag is typically computed by reversing a transformation, "
        "satisfying a checker function, or extracting embedded data."
    ),
    planner_focus=(
        "Prioritize: 1) File triage to identify binary format and architecture, "
        "2) String extraction for hardcoded constants and flag fragments, "
        "3) Disassembly/decompilation to understand the transform pipeline, "
        "4) Writing and executing an inverse function, "
        "5) Running the binary with instrumented input to capture output."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a reverse engineering CTF challenge. "
        "Focus on understanding transformation pipelines, identifying checker "
        "functions, extracting constants, and constructing inverse operations. "
    ),
    analysis_strategy=(
        "For reversing challenges: identify the main transform chain (XOR with key, "
        "byte shuffles, custom S-boxes, RC4, TEA, etc.). Extract all hardcoded "
        "constants, lookup tables, and encoded byte arrays. Determine if the "
        "challenge uses a known algorithm or a custom one. Look for checker "
        "functions that compare against expected output."
    ),
    exploit_strategy=(
        "Write a solver script that reverses the identified transformation. "
        "If the transform is a known cipher, apply the standard decryption. "
        "If it is custom, reconstruct the inverse step by step. "
        "Execute the solver in the container and capture the flag output."
    ),
    flag_recovery_hints=[
        "Run strings/objdump on binaries to find encoded flag data",
        "Look for comparison functions that validate flag input",
        "XOR encoded data with extracted keys",
        "Try running the binary with various inputs and observe output patterns",
        "Use ltrace/strace to trace library calls for crypto functions",
    ],
    solver_technique_examples=[
        "# XOR decrypt: key=[0x3f,0x42,...]; flag=bytes(c^k for c,k in zip(enc,key))",
        "# Inverse transform: for i in range(len(data)-1,-1,-1): data[i] ^= data[i-1]",
        "# String extraction: subprocess.run(['strings', binary], capture_output=True)",
        "# Brute-force checker: for c in range(32,127): if check(chr(c)): flag+=chr(c)",
        "# Z3 solver: from z3 import *; s=Solver(); s.add(constraints); s.check()",
    ],
))

# ---------------------------------------------------------------------------
# Cryptography
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="crypto",
    objective_hint=(
        "Identify the cipher/algorithm used, look for known-plaintext attacks "
        "(file headers like PNG magic bytes), weak keys, small primes, "
        "or reversible operations. Try running any bundled scripts and check "
        "if output can be decoded. Derive the flag mathematically when possible."
    ),
    planner_system=(
        "You are planning a cryptography CTF challenge. Crypto challenges require "
        "identifying and breaking or exploiting weaknesses in cryptographic "
        "implementations. Common themes: RSA with small primes or shared factors, "
        "block cipher ECB mode, XOR with repeating key, LFSR, custom ciphers, "
        "and mathematical attacks on number theory."
    ),
    planner_focus=(
        "Prioritize: 1) Source code review to identify the algorithm, "
        "2) Parameter extraction (keys, moduli, ciphertexts, IVs), "
        "3) Mathematical analysis of the cryptosystem weaknesses, "
        "4) Writing and executing a decryption/solver script, "
        "5) Known-plaintext attacks if partial plaintext is available."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a cryptography CTF challenge. "
        "Focus on identifying the cryptographic algorithm, extracting parameters, "
        "and finding mathematical or implementation weaknesses to exploit. "
    ),
    analysis_strategy=(
        "For crypto challenges: identify which algorithm is used (RSA, AES, DES, "
        "XOR, custom). Extract all parameters: public keys, moduli, exponents, "
        "ciphertexts, IVs, nonces. Check for weak parameters: small RSA primes "
        "(factorable via factordb), reused nonces, ECB mode, short XOR keys. "
        "Look for known-plaintext opportunities (file headers, flag format prefix)."
    ),
    exploit_strategy=(
        "Apply the appropriate mathematical attack: factor RSA modulus if small, "
        "use Wiener's attack for large e, Hastad's broadcast attack for small e, "
        "XOR ciphertext with known plaintext to recover key, break LFSR with "
        "known output bits. Write a Python solver script using standard crypto "
        "libraries (pycryptodome, gmpy2, sympy) and execute it."
    ),
    flag_recovery_hints=[
        "Factor RSA modulus using factordb or yafu",
        "XOR ciphertext with known flag format prefix to recover key fragment",
        "Check if ECB mode leaks block patterns",
        "Try small exponent attacks for RSA",
        "Use z3 or sage for constraint-based solving",
    ],
    solver_technique_examples=[
        "# AES decrypt: from Crypto.Cipher import AES; AES.new(key,AES.MODE_CBC,iv).decrypt(ct)",
        "# RSA: from gmpy2 import invert; d=invert(e,(p-1)*(q-1)); m=pow(c,d,n); print(m.to_bytes())",
        "# XOR key recovery: key=bytes(c^p for c,p in zip(ciphertext, b'flag{'))",
        "# Hash brute: from itertools import product; [hashlib.md5(x).hexdigest() for x in candidates]",
        "# Factordb: requests.get(f'http://factordb.com/api?query={n}').json()",
    ],
))

# ---------------------------------------------------------------------------
# Forensics
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="forensics",
    objective_hint=(
        "Inspect file formats and metadata, extract embedded files, "
        "analyze packet captures for credentials and transferred data, "
        "check disk images for hidden partitions or deleted files, "
        "and examine git repositories for sensitive history."
    ),
    planner_system=(
        "You are planning a forensics CTF challenge. Forensics challenges involve "
        "analyzing digital artifacts: packet captures, disk images, memory dumps, "
        "steganographic images, log files, and git repositories. The flag is "
        "typically hidden within the data and requires careful extraction."
    ),
    planner_focus=(
        "Prioritize: 1) File type identification and metadata extraction, "
        "2) Embedded file extraction (binwalk, foremost, steghide), "
        "3) PCAP analysis for cleartext credentials, HTTP requests, DNS queries, "
        "4) Disk/memory image mounting and deleted file recovery, "
        "5) Git history analysis for leaked secrets in previous commits."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a forensics CTF challenge. "
        "Focus on extracting hidden data from file artifacts, analyzing network "
        "traffic patterns, recovering deleted or embedded content, and identifying "
        "steganographic techniques. "
    ),
    analysis_strategy=(
        "For forensics challenges: use file/binwalk to identify file types and "
        "embedded data. For PCAPs: extract HTTP objects, DNS queries, FTP transfers, "
        "and cleartext credentials. For images: check EXIF metadata, LSB steganography, "
        "and appended data after file EOF. For disk images: mount and search for "
        "deleted files, hidden partitions, and alternate data streams."
    ),
    exploit_strategy=(
        "Apply targeted extraction based on artifact type: "
        "binwalk -e for embedded files, tshark/wireshark for PCAP analysis, "
        "steghide/zsteg for image steganography, testdisk/photorec for disk recovery, "
        "volatility for memory forensics. Check git log --all --diff-filter for "
        "secrets in repository history."
    ),
    flag_recovery_hints=[
        "Run binwalk -e to extract embedded files",
        "Check image metadata with exiftool",
        "Try steghide extract with empty password",
        "Filter PCAP for HTTP POST bodies and DNS TXT records",
        "Search git history: git log --all -p | grep -i flag",
        "Mount disk images and search for recently modified files",
    ],
    solver_technique_examples=[
        "# PCAP: import pyshark; cap=FileCapture('f.pcap'); [p['DNS'].qry_name for p in cap if 'DNS' in p]",
        "# Binwalk: subprocess.run(['binwalk','-e','file.bin'],cwd=files_root)",
        "# Steghide: subprocess.run(['steghide','extract','-sf','img.jpg','-p','','-f'])",
        "# Git history: subprocess.run(['git','log','--all','-p','--'],capture_output=True,cwd=repo)",
        "# Base64 chain: import base64; data=open('f','rb').read(); while True: data=base64.b64decode(data)",
        "# Image LSB: from PIL import Image; bits=''.join(str(px&1) for px in img.getdata())",
    ],
))

# ---------------------------------------------------------------------------
# Pwn (Binary Exploitation)
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="pwn",
    objective_hint=(
        "Enumerate the service, collect banners, test common interactive commands, "
        "identify the binary vulnerability type (buffer overflow, format string, "
        "use-after-free, heap corruption), and probe for memory corruption or "
        "logic vulnerabilities. Write and test an exploit script."
    ),
    planner_system=(
        "You are planning a binary exploitation (pwn) CTF challenge. Pwn challenges "
        "require exploiting memory corruption or logic bugs in compiled binaries to "
        "gain control flow and typically read the flag. Common techniques: buffer "
        "overflow, ROP chains, format string attacks, heap exploitation, ret2libc."
    ),
    planner_focus=(
        "Prioritize: 1) Binary triage - architecture, protections (NX, PIE, canary, RELRO), "
        "2) Vulnerability identification via source review or disassembly, "
        "3) Service interaction to understand the protocol and trigger conditions, "
        "4) Exploit development with pwntools, "
        "5) Flag capture from shell or direct memory read."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a binary exploitation (pwn) CTF challenge. "
        "Focus on identifying memory corruption vectors, protection mechanisms, "
        "and viable exploitation paths (ROP, ret2libc, shellcode, format strings). "
    ),
    analysis_strategy=(
        "For pwn challenges: check binary protections with checksec (NX, PIE, canary, "
        "RELRO). Identify vulnerable functions: gets(), scanf(), sprintf(), strcpy(). "
        "Determine buffer sizes and offsets to return address. Check for format string "
        "vulnerabilities. Identify useful gadgets for ROP chains. Look for win functions "
        "or system() calls already in the binary."
    ),
    exploit_strategy=(
        "Develop a targeted exploit: calculate overflow offset to RIP/EIP, "
        "construct ROP chain or ret2libc payload if NX is enabled, "
        "use format string to leak addresses if PIE/ASLR, "
        "write pwntools script for reliable exploitation, "
        "test against the remote service and capture the flag."
    ),
    flag_recovery_hints=[
        "Use checksec to identify binary protections",
        "Find offset to return address with cyclic pattern",
        "Look for win() or system('/bin/sh') gadgets",
        "Leak libc addresses via format string or GOT",
        "Use pwntools for scripted exploitation",
    ],
    solver_technique_examples=[
        "# Basic overflow: from pwn import *; p=remote(host,port); p.sendline(b'A'*offset+p64(win_addr))",
        "# Format string leak: p.sendline(b'%p.'*20); leaked=p.recvline()",
        "# ROP: from pwn import *; rop=ROP(elf); rop.call('system',[next(elf.search(b'/bin/sh'))])",
        "# ret2libc: libc_base=leaked_addr-libc.symbols['puts']; system=libc_base+libc.symbols['system']",
        "# Simple interaction: p=remote(h,port); p.sendlineafter(b'> ',b'target_address')",
    ],
))

# ---------------------------------------------------------------------------
# Misc
# ---------------------------------------------------------------------------
_register(CategoryPrompts(
    category="misc",
    objective_hint=(
        "Misc challenges can span any domain. Inspect all bundled files carefully, "
        "look for encoded data, programming puzzles, esoteric languages, "
        "and unconventional flag hiding techniques. Be creative and try "
        "multiple approaches."
    ),
    planner_system=(
        "You are planning a miscellaneous CTF challenge. Misc challenges are diverse "
        "and may involve programming puzzles, esoteric languages, encoding chains, "
        "OSINT, jail escapes, or creative problem-solving. Approach with broad "
        "reconnaissance and narrow down based on evidence."
    ),
    planner_focus=(
        "Prioritize: 1) Thorough file triage and content inspection, "
        "2) Encoding/decoding chains (base64, hex, ROT13, morse, etc.), "
        "3) Script execution to observe runtime behavior, "
        "4) Pattern recognition and creative problem-solving, "
        "5) Flag hunting across all discovered artifacts."
    ),
    worker_system_prefix=(
        "You are analyzing evidence from a miscellaneous CTF challenge. "
        "Be creative and consider unconventional approaches. Look for encoding "
        "chains, esoteric languages, hidden messages, and programming puzzles. "
    ),
    analysis_strategy=(
        "For misc challenges: try multiple angles. Check for multi-layer encoding "
        "(base64 → hex → ROT13). Look for esoteric language code (brainfuck, "
        "whitespace, malbolge). Check for steganography in any image files. "
        "Run any scripts and observe output. Look for patterns in data files."
    ),
    exploit_strategy=(
        "Apply the technique matching the identified puzzle type: "
        "decode encoding chains step by step, interpret esoteric languages, "
        "solve programming challenges with a script, bypass jail restrictions "
        "with creative input, and combine partial flag fragments."
    ),
    flag_recovery_hints=[
        "Try decoding with multiple encodings (base64, hex, ROT13, morse)",
        "Run scripts with different inputs/arguments",
        "Look for patterns suggesting esoteric languages",
        "Check file for appended or hidden data sections",
    ],
    solver_technique_examples=[
        "# Decode chain: import base64,codecs; d=base64.b64decode(data); d=bytes.fromhex(d.decode()); d=codecs.decode(d,'rot13')",
        "# Jail escape: __import__('os').system('cat flag*')",
        "# Brute-force: from itertools import product; [try_password(''.join(p)) for p in product(charset,repeat=n)]",
        "# Esoteric: subprocess.run(['bf','program.bf'],capture_output=True)  # brainfuck interpreter",
        "# Pattern solve: data=open('data.txt').readlines(); # parse + compute + print flag",
    ],
))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def get_prompts(category: str | None) -> CategoryPrompts:
    """Return the prompt bundle for *category*, falling back to misc."""
    normalized = (category or "misc").strip().lower()
    return _REGISTRY.get(normalized, _REGISTRY["misc"])


def get_objective_hint(category: str | None, *, has_files: bool, has_scope: bool) -> str:
    """Return a focused objective hint paragraph for the given category."""
    prompts = get_prompts(category)
    parts = [prompts.objective_hint]
    if has_files and not has_scope:
        parts.append(
            "Challenge files are available inside the agent container under "
            "/home/ctfplayer/ctf_files. Inspect them first and derive concrete "
            "flag candidates from the local artifacts."
        )
    return " ".join(parts)


def get_planner_system_prompt(category: str | None, approved_task_types: list[str]) -> str:
    """Build the full LLM planner system prompt for the given category."""
    prompts = get_prompts(category)
    import json
    return (
        f"{prompts.planner_system} "
        f"{prompts.planner_focus} "
        "You operate within the explicitly approved challenge environment and scope only. "
        "Return only JSON matching the PlannerDecision schema. "
        f"You may only propose tasks from this approved list: {json.dumps(approved_task_types)}. "
        "Prioritize the shortest grounded path to the real flag rather than generic coverage. "
        "\n\n"
        "WORKFLOW PHASES — follow the progress.current_phase and progress.phase_guidance:\n"
        "  1. INITIAL → schedule artifact.triage or recon.enumerate_scope\n"
        "  2. TRIAGE_COMPLETE → schedule analysis tasks (source_review, computation_analysis, etc.)\n"
        "  3. ANALYSIS_COMPLETE → MUST schedule 'solve.generate_script' (priority >= 90). "
        "This is the most powerful task — it writes a complete solver script and executes it. "
        "Do NOT keep scheduling more analysis when the phase is ANALYSIS_COMPLETE.\n"
        "  4. EXPLOITATION → if solver failed, schedule another 'solve.generate_script' with "
        "different approach, or gather more targeted evidence.\n"
        "  5. SOLVED → set stop_run=true.\n\n"
        "You MUST always propose at least one new task unless the challenge is SOLVED. "
        "If you cannot find the flag through analysis alone, schedule 'solve.generate_script'. "
        "Exploitation tasks (exploit.*, post_exploit.*) must only be proposed when the asset is in the "
        "authorized_scope AND prior evidence identifies a concrete pivot. "
        "Never propose tasks outside the authorized_scope or the provided challenge files. "
        "Never fabricate vulnerability details, credentials, or flag candidates."
    )


def get_router_system_prompt(category: str | None) -> str:
    """Build the LLM router system prompt for the given category."""
    prompts = get_prompts(category)
    return (
        "You are the worker-router for an authorized CTF challenge-solving workflow. "
        f"The challenge category is '{prompts.category}'. {prompts.analysis_strategy} "
        "Choose exactly one worker from the provided candidates for the current task. "
        "Prefer the worker whose specialization best matches the task input_context, "
        "challenge category, the shortest path to the flag, and the current evidence. "
        "Do not invent worker names. Return only JSON matching WorkerRouteDecision."
    )


def get_worker_system_prompt(
    category: str | None,
    *,
    worker_role: str,
    evidence_type: str,
    output_schema: str,
) -> str:
    """Build a category-aware worker system prompt."""
    prompts = get_prompts(category)
    return (
        f"{prompts.worker_system_prefix}"
        f"{worker_role} "
        f"Return only JSON matching the {output_schema} schema. "
        f"Only emit grounded_flag_candidates and interesting_paths that are directly "
        f"supported by the provided {evidence_type} evidence. "
        "Do not fabricate flags, credentials, or paths not present in the evidence."
    )


def get_analysis_strategy(category: str | None) -> str:
    """Return the analysis strategy text for the given category."""
    return get_prompts(category).analysis_strategy


def get_exploit_strategy(category: str | None) -> str:
    """Return the exploit strategy text for the given category."""
    return get_prompts(category).exploit_strategy


def get_flag_hints(category: str | None) -> list[str]:
    """Return category-specific flag recovery hints."""
    return list(get_prompts(category).flag_recovery_hints)


def get_solver_technique_examples(category: str | None) -> list[str]:
    """Return code snippet examples for solver generation."""
    return list(get_prompts(category).solver_technique_examples)


def build_worker_context(
    state_metadata: dict[str, Any],
) -> dict[str, str]:
    """Extract category and return useful prompt fragments for workers."""
    challenge = state_metadata.get("challenge", {})
    category = str(challenge.get("category") or "misc").lower()
    prompts = get_prompts(category)
    return {
        "category": category,
        "analysis_strategy": prompts.analysis_strategy,
        "exploit_strategy": prompts.exploit_strategy,
        "worker_system_prefix": prompts.worker_system_prefix,
        "flag_hints": "\n".join(f"- {hint}" for hint in prompts.flag_recovery_hints),
    }
