"""Todo semantic-family classification."""

from __future__ import annotations


def family_for(goal: str, context: dict[str, object] | None = None) -> str:
    context = context or {}
    explicit = str(context.get("family") or "").strip()
    if explicit and explicit != "other":
        return explicit
    derived = derive_family_from_goal(goal)
    if derived != "other":
        return derived
    return explicit or "other"


def derive_family_from_goal(goal: str) -> str:
    text = goal.lower()
    if (
        "disassembl" in text
        or "objdump" in text
        or "machine code" in text
        or "binary analysis" in text
        or "binary-analysis" in text
        or "reverse engineer" in text
        or "reverse-engineer" in text
        or "reversing" in text
        or "decompile" in text
        or "radare" in text
        or "gdb" in text
    ):
        return "binary-analysis"
    if "run" in text and "binary" in text:
        return "binary-run"
    if "binary" in text and any(
        token in text for token in ("algorithm", "analy", "inspect", "recover")
    ):
        return "binary-analysis"
    if any(
        token in text
        for token in (
            "decrypt",
            "keystream",
            "known-plaintext",
            "lfsr",
            "cipher",
            "xor",
        )
    ):
        return "crypto-decrypt"
    if "flag" in text and any(
        token in text for token in ("recover", "validate", "candidate")
    ):
        return "flag-recovery"
    if any(token in text for token in ("inventory", "classify", "triage")):
        return "artifact-inventory"
    if any(
        token in text for token in ("list", "enumerate", "inspect", "identify")
    ) and any(
        token in text
        for token in ("file", "files", "artifact", "artifacts", "directory")
    ):
        return "artifact-inventory"
    if "scope" in text or "recon" in text:
        return "recon"
    return "other"


def local_artifact_recovery(
    goal_l: str, context: dict[str, object], family: str
) -> bool:
    if family not in {"crypto-decrypt", "flag-recovery"}:
        return False
    if not any(
        context.get(key)
        for key in (
            "files_root",
            "challenge_files",
            "source_files",
            "binary_files",
            "data_file",
            "paths",
        )
    ):
        return False
    if any(
        token in goal_l
        for token in (
            "http",
            "remote",
            "service",
            "socket",
            "tcp",
            "url",
            "web",
        )
    ):
        return False
    return any(
        token in goal_l
        for token in (
            "cipher",
            "decode",
            "decrypt",
            "keystream",
            "lfsr",
            "plaintext",
            "port the source",
            "reverse transformation",
            "xor",
        )
    )


def compound_disassembly_and_exploit(goal: str) -> bool:
    text = goal.lower()
    has_disasm = any(token in text for token in ("disassembl", "objdump", "reverse"))
    has_script = any(token in text for token in ("write a python", "script", "decrypt"))
    sequencing = any(token in text for token in (" then ", " and then ", " after "))
    return has_disasm and has_script and sequencing
