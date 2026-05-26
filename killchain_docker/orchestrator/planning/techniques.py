"""Structured planning profiles for planner and routing policy."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    """One ATT&CK-inspired planning profile.

    The full object can support deterministic policy. Prompt renderings expose
    only identifiers and grounding facets, not prose execution playbooks.
    """

    family: str
    tactic: str
    phase: str
    categories: tuple[str, ...]
    objective: str
    evidence_to_seek: tuple[str, ...]
    failure_escape: tuple[str, ...]

    def applies_to(self, category: str) -> bool:
        return "*" in self.categories or category in self.categories

    def to_prompt_dict(self) -> dict[str, object]:
        return {
            "family": self.family,
            "tactic": self.tactic,
            "phase": self.phase,
            "categories": list(self.categories),
            "evidence_facets": list(self.evidence_to_seek),
        }


TECHNIQUES: tuple[Technique, ...] = (
    Technique(
        family="artifact-inventory",
        tactic="scope-and-artifact-discovery",
        phase="recon",
        categories=("*",),
        objective="Inventory challenge files, service scope, formats, and obvious flag surfaces.",
        evidence_to_seek=(
            "file types",
            "entrypoints",
            "service URLs/ports",
            "flag format",
        ),
        failure_escape=("Switch from listing to content sampling or service probing.",),
    ),
    Technique(
        family="source-review",
        tactic="implementation-analysis",
        phase="analysis",
        categories=("web", "crypto", "misc", "forensics"),
        objective="Review source/config/scripts for algorithm, auth, parsing, or secret-handling mistakes.",
        evidence_to_seek=(
            "constants",
            "input parsers",
            "crypto parameters",
            "auth/session logic",
        ),
        failure_escape=(
            "Run minimal reproductions instead of re-reading the same files.",
        ),
    ),
    Technique(
        family="binary-static",
        tactic="static-reversing",
        phase="analysis",
        categories=("rev", "pwn", "crypto"),
        objective="Extract strings, symbols, mitigations, disassembly windows, and checker/decryptor logic.",
        evidence_to_seek=(
            "interesting strings",
            "control-flow checks",
            "mitigations",
            "data tables",
        ),
        failure_escape=(
            "Change lens: strings -> symbols -> disassembly -> decompiler-like pseudocode.",
        ),
    ),
    Technique(
        family="binary-dynamic",
        tactic="dynamic-observation",
        phase="analysis",
        categories=("rev", "pwn"),
        objective="Run the binary with controlled inputs to observe branches, crashes, prompts, and outputs.",
        evidence_to_seek=(
            "stdout/stderr",
            "exit status",
            "crash offset",
            "branch-dependent output",
        ),
        failure_escape=(
            "Reduce input size, add tracing, or inspect only the divergent branch.",
        ),
    ),
    Technique(
        family="crypto-model",
        tactic="cryptanalytic-model-recovery",
        phase="analysis",
        categories=("crypto",),
        objective="Infer cipher family, state update, key material, encoding, and known-plaintext constraints.",
        evidence_to_seek=(
            "headers",
            "known plaintext",
            "keystream relation",
            "modulus/group parameters",
        ),
        failure_escape=(
            "Try a different model family or verify byte order/packing before repeating code.",
        ),
    ),
    Technique(
        family="algorithm-verification",
        tactic="source-to-solver-closure",
        phase="analysis",
        categories=("crypto", "rev", "misc"),
        objective=(
            "Build a bounded solver harness that faithfully ports observed or hinted "
            "algorithm logic, then proves the port with small checks before deriving a candidate."
        ),
        evidence_to_seek=(
            "parameter extraction",
            "round-trip or differential self-check",
            "bounded execution evidence",
            "candidate evidence",
        ),
        failure_escape=("Use observed execution feedback before changing families.",),
    ),
    Technique(
        family="web-surface",
        tactic="web-reconnaissance",
        phase="recon",
        categories=("web",),
        objective="Map routes, parameters, cookies, source leaks, and server-side framework clues.",
        evidence_to_seek=(
            "routes",
            "forms",
            "cookies",
            "status codes",
            "source/config leaks",
        ),
        failure_escape=(
            "Probe alternate methods, encodings, and static assets before exploit planning.",
        ),
    ),
    Technique(
        family="web-exploit",
        tactic="application-exploitation",
        phase="exploit",
        categories=("web",),
        objective="Exploit a grounded web finding such as auth bypass, injection, traversal, or deserialization.",
        evidence_to_seek=(
            "finding_id",
            "endpoint_ref",
            "payload effect",
            "session/cookie state",
        ),
        failure_escape=(
            "Change payload class only when evidence shows the current class is blocked.",
        ),
    ),
    Technique(
        family="pwn-surface",
        tactic="memory-corruption-analysis",
        phase="analysis",
        categories=("pwn",),
        objective="Identify mitigations, input path, memory layout clues, and controllable crash primitive.",
        evidence_to_seek=(
            "checksec",
            "crash offset",
            "controlled registers",
            "useful gadgets/functions",
        ),
        failure_escape=(
            "Switch between static mitigation review, fuzzing, and debugger inspection.",
        ),
    ),
    Technique(
        family="pwn-exploit",
        tactic="exploit-construction",
        phase="exploit",
        categories=("pwn",),
        objective="Build a grounded exploit from a known primitive and validate it in the authorized target.",
        evidence_to_seek=(
            "vulnerability_id",
            "offset",
            "target symbol/address",
            "I/O transcript",
        ),
        failure_escape=(
            "Re-derive offsets and bad bytes before changing exploit strategy.",
        ),
    ),
    Technique(
        family="forensics-extract",
        tactic="artifact-recovery",
        phase="analysis",
        categories=("forensics", "misc"),
        objective="Recover hidden, deleted, embedded, compressed, or transformed data from artifacts.",
        evidence_to_seek=(
            "embedded files",
            "metadata",
            "magic bytes",
            "archives",
            "pcap streams",
        ),
        failure_escape=(
            "Change extractor or layer ordering; avoid rerunning the same extractor blindly.",
            "For PCAPs, if a display filter is empty, inspect conversations or packet payloads; "
            "do not treat raw container-byte magic search as stream reassembly.",
        ),
    ),
    Technique(
        family="flag-recovery",
        tactic="candidate-recovery",
        phase="analysis",
        categories=("*",),
        objective="Derive a concrete flag candidate from grounded evidence or computed output.",
        evidence_to_seek=(
            "candidate source",
            "normalization/encoding",
            "evidence_refs",
        ),
        failure_escape=(
            "If candidates are malformed, inspect generation logic instead of guessing variants.",
        ),
    ),
    Technique(
        family="flag-validation",
        tactic="objective-validation",
        phase="flag_validation",
        categories=("*",),
        objective="Validate a concrete candidate already present in state or todo context.",
        evidence_to_seek=("candidate_flag", "validation result", "source evidence"),
        failure_escape=("Return to analysis when no concrete candidate exists.",),
    ),
)


def technique_matrix_for(category: str, *, limit: int = 10) -> list[dict[str, object]]:
    """Return prompt-safe planning profiles relevant to a challenge category."""

    normalized = (category or "misc").strip().lower()
    selected = [item for item in TECHNIQUES if item.applies_to(normalized)]
    return [item.to_prompt_dict() for item in selected[:limit]]
