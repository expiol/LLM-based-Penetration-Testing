"""Prompts for miscellaneous challenges (default fallback)."""

from __future__ import annotations

from killchain_docker.prompts.types import CategoryPrompts, register

register(CategoryPrompts(
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
    script_technique_examples=[
        "# Decode chain: import base64,codecs; d=base64.b64decode(data); d=bytes.fromhex(d.decode()); d=codecs.decode(d,'rot13')",
        "# Jail escape: __import__('os').system('cat flag*')",
        "# Brute-force: from itertools import product; [try_password(''.join(p)) for p in product(charset,repeat=n)]",
        "# Esoteric: subprocess.run(['bf','program.bf'],capture_output=True)  # brainfuck interpreter",
        "# Pattern solve: data=open('data.txt').readlines(); # parse + compute + print flag",
    ],
))
