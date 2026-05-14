"""Prompts for reverse engineering challenges."""

from __future__ import annotations

from killchain_docker.prompts.types import CategoryPrompts, register

register(CategoryPrompts(
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
        "2) ltrace/strace to observe library calls and I/O without full disassembly, "
        "3) String extraction for hardcoded constants and flag fragments, "
        "4) Disassembly/decompilation to understand the transform pipeline, "
        "5) Writing and executing an inverse function, "
        "6) Running the binary with instrumented input to capture output."
    ),
    analysis_strategy=(
        "For reversing challenges: identify the main transform chain (XOR with key, "
        "byte shuffles, custom S-boxes, RC4, TEA, etc.). Extract all hardcoded "
        "constants, lookup tables, and encoded byte arrays. Determine if the "
        "challenge uses a known algorithm or a custom one. Look for checker "
        "functions that compare against expected output."
    ),
    exploit_strategy=(
        "Write a script that reverses the identified transformation. "
        "If the transform is a known cipher, apply the standard decryption. "
        "If it is custom, reconstruct the inverse step by step. "
        "Execute the script in the container and capture the flag output."
    ),
    flag_recovery_hints=[
        "Run strings/objdump on binaries to find encoded flag data",
        "Use ltrace to trace library calls (crypto functions, strcmp, memcmp)",
        "Use strace to observe file I/O and syscalls",
        "Look for comparison functions that validate flag input",
        "XOR encoded data with extracted keys",
        "Try running the binary with various inputs and observe output patterns",
        "Use ROPgadget to find useful gadgets if exploitation is needed",
    ],
))
