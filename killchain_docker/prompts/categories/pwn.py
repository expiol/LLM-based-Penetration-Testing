"""Prompts for binary-exploitation (pwn) challenges."""

from __future__ import annotations

from killchain_docker.prompts.types import CategoryPrompts, register

register(CategoryPrompts(
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
