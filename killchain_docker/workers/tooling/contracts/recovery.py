"""Metadata contracts for password recovery and mobile decompilation."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability

RECOVERY_TOOL_METADATA_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.JOHN: {
        "required": ["path"],
        "optional": ["wordlist", "format", "extra_args"],
        "notes": "Password cracking. path is a hash file. Cracked results shown via --show.",
    },
    ToolCapability.FCRACKZIP: {
        "required": ["path"],
        "optional": ["wordlist", "extra_args"],
        "notes": "ZIP password cracking. wordlist default rockyou.txt.",
    },
    ToolCapability.JADX: {
        "required": ["path"],
        "optional": ["output_dir"],
        "notes": "APK/DEX decompilation. Outputs Java source files.",
    },
}
