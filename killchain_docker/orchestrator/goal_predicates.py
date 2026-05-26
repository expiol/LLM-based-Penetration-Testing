"""Goal-text predicates used by todo normalization and workers."""

from __future__ import annotations


def goal_requires_executable_interaction(goal_l: str) -> bool:
    return any(
        (
            token in goal_l
            for token in (
                "authenticate",
                "connect",
                "deliver",
                "execute",
                "exploit",
                "interact",
                "payload",
                "run",
                "send",
                "service",
            )
        )
    )


def goal_requires_binary_static_analysis(goal_l: str) -> bool:
    binary_terms = ("binary", "elf", "executable", "program")
    analysis_terms = (
        "checksec",
        "control-flow",
        "control flow",
        "decompile",
        "disassembl",
        "entry function",
        "function",
        "gadget",
        "mitigation",
        "objdump",
        "radare",
        "reverse engineer",
        "rop",
        "section",
        "symbol",
    )
    if any((term in goal_l for term in analysis_terms)):
        return True
    return any((term in goal_l for term in binary_terms)) and any(
        (term in goal_l for term in ("analy", "inspect", "locate", "static"))
    )


def goal_requires_artifact_extraction(goal_l: str) -> bool:
    has_extraction_action = any(
        (
            token in goal_l
            for token in (
                "carve",
                "decompress",
                "expand",
                "extract",
                "unarchive",
                "unpack",
            )
        )
    )
    if not has_extraction_action:
        return False
    return any(
        (
            token in goal_l
            for token in (
                "archive",
                "container",
                "directory",
                "embedded",
                "file",
                "payload",
                "source tree",
                "working directory",
            )
        )
    )


def goal_requires_raw_artifact_access(goal_l: str) -> bool:
    has_raw_access_action = any(
        (
            token in goal_l
            for token in (
                "cat ",
                "complete",
                "dump",
                "entire",
                "every line",
                "full",
                "line-by-line",
                "raw",
                "read",
                "recursively",
                "search",
                "show",
            )
        )
    )
    if not has_raw_access_action:
        return False
    return any(
        (
            token in goal_l
            for token in (
                "artifact",
                "content",
                "directory",
                "directories",
                "file",
                "files",
                "raw text",
                "source",
                "tree",
            )
        )
    )


def goal_needs_files(goal_l: str) -> bool:
    return any(
        (
            token in goal_l
            for token in (
                "file",
                "artifact",
                "source",
                "binary",
                "flag",
                "decrypt",
                "disassembl",
                "objdump",
                "lfsr",
            )
        )
    )
