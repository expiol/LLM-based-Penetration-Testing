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
        "Use ROPgadget to enumerate ROP gadgets for chain construction",
        "Use one_gadget to find one-shot shell gadgets in libc",
        "Leak libc addresses via format string or GOT",
        "Use pwntools for scripted exploitation",
    ],
))
