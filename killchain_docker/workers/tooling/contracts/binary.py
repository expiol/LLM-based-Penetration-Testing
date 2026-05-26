"""Metadata contracts for binary analysis and tracing capabilities."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability

BINARY_TOOL_METADATA_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.BINWALK: {
        "required": ["path"],
        "optional": ["extract", "files_root", "max_extract_mb"],
        "notes": (
            "Firmware/binary analysis. Set extract=true to carve embedded files in a "
            "bounded disposable workspace; max_extract_mb caps extraction growth."
        ),
    },
    ToolCapability.RADARE2: {
        "required": ["path"],
        "optional": ["commands"],
        "notes": "Binary analysis with r2. commands default 'aaa; afl; pdf @ main'. Use r2 command syntax.",
    },
    ToolCapability.OBJDUMP: {
        "required": ["path"],
        "optional": ["flags"],
        "notes": "Disassembly. flags default '-d -M intel'.",
    },
    ToolCapability.GDB: {
        "required": ["path"],
        "optional": ["commands"],
        "notes": "Debugging. commands piped to gdb -batch. e.g. 'info functions' or 'break main\\nrun\\nbt'.",
    },
    ToolCapability.CHECKSEC: {
        "required": ["path"],
        "optional": [],
        "notes": "Binary security properties (NX, PIE, canary, RELRO). Returns protection status and attack surface hints.",
    },
    ToolCapability.LTRACE: {
        "required": ["path"],
        "optional": ["args", "filter", "input_data"],
        "notes": (
            "Trace library calls. Reveals strcmp/memcmp args (potential flags/passwords), "
            "crypto function parameters, buffer sizes. "
            "filter e.g. 'strcmp+memcmp+strncmp'. input_data sent via stdin."
        ),
    },
    ToolCapability.STRACE: {
        "required": ["path"],
        "optional": ["args", "filter", "input_data"],
        "notes": (
            "Trace system calls. Reveals file paths accessed (open/openat), "
            "network connections, and runtime behavior. "
            "filter e.g. 'trace=open,read,write' or 'trace=network'. input_data sent via stdin."
        ),
    },
}
