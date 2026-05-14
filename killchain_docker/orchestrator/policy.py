"""Core orchestration policy.

This module is the gate between untrusted tool/LLM output and durable run
state.  Tools may report many interesting strings and planners may propose
many tasks; only policy-approved facts and todos should enter the core state
machine.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from killchain_docker.state import FlagCandidate, TodoItem, TodoPhase, TodoStatus
from killchain_docker.state.constants import (
    FLAG_BARE_TOKEN_SHAPE,
    FLAG_PREFIX_SHAPE,
    validatable_flag_candidate,
)

if TYPE_CHECKING:  # pragma: no cover
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state import RunState


DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"
_ESCAPED_BYTE_RE = re.compile(r"\\x[0-9a-fA-F]{2}|\\[0abfnrtv]")
_PREFIX_FROM_FORMAT_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\\?\{|\{)")


@dataclass(frozen=True)
class CandidateDecision:
    accepted: bool
    reason: str = ""


class CandidatePolicy:
    """Validate and select flag candidates before they mutate run state."""

    @classmethod
    def decision_for_state(cls, state: "RunState", candidate: str) -> CandidateDecision:
        challenge = state.metadata.get("challenge", {}) or {}
        return cls.decision(candidate, flag_format=challenge.get("flag_format"))

    @classmethod
    def accepts_for_state(cls, state: "RunState", candidate: str) -> bool:
        return cls.decision_for_state(state, candidate).accepted

    @classmethod
    def decision(cls, candidate: str, *, flag_format: object = None) -> CandidateDecision:
        text = str(candidate or "").strip()
        if not text:
            return CandidateDecision(False, "empty_candidate")
        if cls._looks_like_bytes_repr_flag(text):
            return CandidateDecision(False, "escaped_byte_candidate")
        if not validatable_flag_candidate(text):
            return CandidateDecision(False, "invalid_candidate_shape")

        expected_prefix = cls._expected_prefix(flag_format)
        bare_mode = cls._bare_token_mode(flag_format)
        unknown_mode = flag_format is None

        if bare_mode:
            if FLAG_BARE_TOKEN_SHAPE.fullmatch(text):
                return CandidateDecision(True)
            return CandidateDecision(False, "prefix_candidate_for_bare_token_challenge")

        if FLAG_BARE_TOKEN_SHAPE.fullmatch(text) and not FLAG_PREFIX_SHAPE.fullmatch(text):
            if unknown_mode:
                return CandidateDecision(True)
            return CandidateDecision(False, "bare_token_for_prefix_challenge")
        if not FLAG_PREFIX_SHAPE.fullmatch(text):
            return CandidateDecision(False, "invalid_prefix_candidate")
        if expected_prefix and not text.startswith(expected_prefix + "{"):
            return CandidateDecision(False, "wrong_flag_prefix")
        return CandidateDecision(True)

    @classmethod
    def validation_ready_candidates(cls, state: "RunState") -> list[FlagCandidate]:
        ready: list[FlagCandidate] = []
        for candidate in state.flag_candidates.values():
            if candidate.validated is False or candidate.rejected_reason:
                continue
            if cls.accepts_for_state(state, candidate.value):
                ready.append(candidate)
        return ready

    @classmethod
    def first_candidate_from_context(
        cls,
        state: "RunState",
        context: dict[str, Any],
        goal: str = "",
    ) -> str | None:
        for key in (
            "candidate_flag",
            "candidate_flags",
            "flag_candidate",
            "flag_candidates",
        ):
            value = context.get(key)
            values = value if isinstance(value, list) else [value]
            for item in values:
                text = str(item or "").strip()
                if text and cls.accepts_for_state(state, text):
                    return text

        from killchain_docker.reasoning.flag import extract_flag_candidates

        for candidate in extract_flag_candidates(goal):
            if cls.accepts_for_state(state, candidate):
                return candidate
        return None

    @staticmethod
    def _bare_token_mode(flag_format: object) -> bool:
        return flag_format is not None and str(flag_format).strip() == ""

    @staticmethod
    def _expected_prefix(flag_format: object) -> str | None:
        raw = str(flag_format or "").strip()
        if not raw:
            return None
        match = _PREFIX_FROM_FORMAT_RE.match(raw)
        if not match:
            return None
        prefix = match.group(1)
        return prefix if prefix.replace("_", "").isalnum() else None

    @staticmethod
    def _looks_like_bytes_repr_flag(candidate: str) -> bool:
        if "{" not in candidate or not candidate.endswith("}"):
            return False
        _prefix, _sep, body = candidate.partition("{")
        body = body[:-1]
        escaped = _ESCAPED_BYTE_RE.findall(body)
        if "\\x" in body:
            return True
        return len(escaped) >= 2


class TodoPolicy:
    """Normalize high-level todos and assign stable semantic families."""

    @classmethod
    def normalize(cls, todo: "PlannedTodo", state: "RunState") -> "PlannedTodo":
        context = todo.context
        challenge = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge.get("files", []) or [])
        goal_l = todo.goal.lower()

        family = cls.family_for(todo.goal, context)
        context.setdefault("family", family)

        if challenge_files and cls._goal_needs_files(goal_l):
            context.setdefault("files_root", DEFAULT_FILES_ROOT)
            context.setdefault("challenge_files", challenge_files)

        candidate = CandidatePolicy.first_candidate_from_context(state, context, todo.goal)
        if candidate:
            context["candidate_flag"] = candidate
            todo.phase = TodoPhase.FLAG_VALIDATION
        elif todo.phase == TodoPhase.FLAG_VALIDATION and CandidatePolicy.validation_ready_candidates(state):
            context["candidate_flag"] = CandidatePolicy.validation_ready_candidates(state)[0].value
            todo.phase = TodoPhase.FLAG_VALIDATION
        elif todo.phase == TodoPhase.FLAG_VALIDATION:
            todo.phase = TodoPhase.ANALYSIS

        if cls._is_compound_disassembly_and_exploit(todo.goal):
            todo.phase = TodoPhase.ANALYSIS
            context["family"] = "binary-disassembly"
            context.setdefault("capability_hint", "binary.disassemble")
            todo.goal = (
                "Extract precise binary algorithm evidence needed for the next "
                "decryption attempt."
            )
            todo.success_criteria = [
                "Capture the exact algorithm or loop evidence needed for a later script.",
            ]

        if not todo.dedupe_key:
            todo.dedupe_key = cls.default_key(todo)
        return todo

    @classmethod
    def default_key(cls, todo: "PlannedTodo | TodoItem") -> str:
        context = todo.context or {}
        family = str(context.get("family") or cls.family_for(todo.goal, context))
        important: list[str] = [str(todo.phase), family]
        for key in (
            "scope",
            "files_root",
            "asset_id",
            "base_url",
            "hostname",
            "candidate_flag",
            "novelty_key",
            "capability_hint",
        ):
            value = context.get(key)
            if value:
                important.append(str(value))
        for key in (
            "challenge_files",
            "source_files",
            "binary_files",
            "archive_files",
            "database_files",
            "pcap_files",
            "repo_paths",
            "paths",
            "seed_terms",
            "evidence_ids",
        ):
            value = context.get(key)
            if isinstance(value, list) and value:
                important.append(",".join(str(item) for item in value[:8]))
        return "todo:" + ":".join(important)

    @staticmethod
    def family_for(goal: str, context: dict[str, Any] | None = None) -> str:
        context = context or {}
        explicit = str(context.get("family") or "").strip()
        if explicit:
            return explicit
        text = goal.lower()
        if "lfsr" in text and any(token in text for token in ("decrypt", "keystream", "xor")):
            return "lfsr-decrypt"
        if "lfsr" in text:
            return "lfsr-analysis"
        if "disassembl" in text or "objdump" in text or "machine code" in text:
            return "binary-disassembly"
        if "run" in text and "binary" in text:
            return "binary-run"
        if "decrypt" in text or "keystream" in text or "known-plaintext" in text:
            return "decrypt-keystream"
        if "flag" in text and any(token in text for token in ("recover", "validate", "candidate")):
            return "flag-recovery"
        if "inventory" in text or "classify" in text:
            return "artifact-inventory"
        if "scope" in text or "recon" in text:
            return "recon"
        return "other"

    @staticmethod
    def _goal_needs_files(goal_l: str) -> bool:
        return any(
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

    @staticmethod
    def _is_compound_disassembly_and_exploit(goal: str) -> bool:
        text = goal.lower()
        has_disasm = any(token in text for token in ("disassembl", "objdump", "reverse"))
        has_script = any(token in text for token in ("write a python", "script", "decrypt"))
        sequencing = any(token in text for token in (" then ", " and then ", " after "))
        return has_disasm and has_script and sequencing


class ProgressPolicy:
    """Detect stalled todo families and suppress repeated failed strategies."""

    FAILURE_COOLDOWN_THRESHOLD = 2

    @classmethod
    def allows(cls, todo: "PlannedTodo", state: "RunState") -> tuple[bool, str]:
        family = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
        if family in {"artifact-inventory", "flag-recovery", "recon"}:
            return True, ""
        failed = cls._failed_or_partial_count(state, family)
        if failed < cls.FAILURE_COOLDOWN_THRESHOLD:
            return True, ""
        if cls._has_new_novelty(todo, state, family):
            return True, ""
        return False, f"family {family!r} is in cooldown after {failed} failed/partial attempt(s)"

    @classmethod
    def stagnation_snapshot(cls, state: "RunState") -> dict[str, Any]:
        counts = Counter()
        failed_counts = Counter()
        for todo in state.todos:
            family = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
            counts[family] += 1
            if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
                failed_counts[family] += 1
        return {
            "family_counts": dict(counts),
            "failed_or_partial_family_counts": dict(failed_counts),
            "cooldown_families": sorted(
                family
                for family, count in failed_counts.items()
                if count >= cls.FAILURE_COOLDOWN_THRESHOLD
            ),
        }

    @classmethod
    def _failed_or_partial_count(cls, state: "RunState", family: str) -> int:
        count = 0
        for todo in state.todos:
            current = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
            if current != family:
                continue
            if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
                count += 1
        return count

    @staticmethod
    def _has_new_novelty(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
        novelty = str(todo.context.get("novelty_key") or "").strip()
        if novelty:
            previous = {
                str(item.context.get("novelty_key") or "").strip()
                for item in state.todos
                if str(item.context.get("family") or TodoPolicy.family_for(item.goal, item.context)) == family
            }
            return novelty not in previous

        evidence_ids = {
            str(item).strip()
            for item in (todo.context.get("evidence_ids") or [])
            if str(item).strip()
        }
        if not evidence_ids:
            return False
        previous_ids: set[str] = set()
        for item in state.todos:
            current = str(item.context.get("family") or TodoPolicy.family_for(item.goal, item.context))
            if current != family:
                continue
            previous_ids.update(
                str(eid).strip()
                for eid in (item.context.get("evidence_ids") or [])
                if str(eid).strip()
            )
        return not evidence_ids.issubset(previous_ids)


class RagPolicy:
    """Decide whether retrieved writeups should continue to guide planning."""

    @staticmethod
    def suppress_related_writeups(state: "RunState") -> bool:
        rag = state.metadata.get("rag")
        if isinstance(rag, dict) and rag.get("policy") == "contradicted":
            return True
        snapshot = ProgressPolicy.stagnation_snapshot(state)
        failed = snapshot.get("failed_or_partial_family_counts", {})
        if isinstance(failed, dict) and int(failed.get("lfsr-decrypt") or 0) >= 2:
            if isinstance(rag, dict):
                rag["policy"] = "contradicted"
            return True
        return False
