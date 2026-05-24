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

from killchain_docker.state import (
    DispatchIntent,
    FlagCandidate,
    TodoItem,
    TodoPhase,
    TodoStatus,
    WorkerResult,
    artifact_followup_capability,
    facts_from_artifact,
)
from killchain_docker.state.constants import (
    DEFAULT_FILES_ROOT,
    bare_token_shape,
    flag_prefix_shape,
    looks_like_escaped_byte_candidate,
    validatable_flag_candidate,
)

if TYPE_CHECKING:  # pragma: no cover
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo
    from killchain_docker.state import RunState


_PREFIX_FROM_FORMAT_RE = re.compile(r"^([A-Za-z0-9_]+)(?:\\?\{|\{)")


@dataclass(frozen=True)
class CandidateDecision:
    accepted: bool
    reason: str = ""


class ContextRefPolicy:
    """Resolve LLM-provided context references against durable state ids."""

    @staticmethod
    def values(context: dict[str, Any], *keys: str) -> set[str]:
        refs: set[str] = set()
        for key in keys:
            value = context.get(key)
            if value is None or isinstance(value, bool):
                continue
            if isinstance(value, str):
                text = value.strip()
                if text:
                    refs.add(text)
                continue
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    if item is None or isinstance(item, bool):
                        continue
                    text = str(item).strip()
                    if text:
                        refs.add(text)
        return refs

    @classmethod
    def refs_existing(
        cls,
        context: dict[str, Any],
        records: dict[str, Any],
        *keys: str,
    ) -> bool:
        refs = cls.values(context, *keys)
        return bool(refs and refs.issubset(records.keys()))


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
        if looks_like_escaped_byte_candidate(text):
            return CandidateDecision(False, "escaped_byte_candidate")
        if not validatable_flag_candidate(text):
            return CandidateDecision(False, "invalid_candidate_shape")

        expected_prefix = cls._expected_prefix(flag_format)
        # Unknown mode: flag_format is None or empty — accept any valid shape
        unknown_mode = not str(flag_format or "").strip()

        if bare_token_shape(text) and not flag_prefix_shape(text):
            if unknown_mode:
                return CandidateDecision(True)
            return CandidateDecision(False, "bare_token_for_prefix_challenge")
        if not flag_prefix_shape(text):
            return CandidateDecision(False, "invalid_prefix_candidate")
        if expected_prefix and not text.startswith(expected_prefix + "{"):
            return CandidateDecision(False, "wrong_flag_prefix")
        return CandidateDecision(True)

    @classmethod
    def derived_candidates(cls, candidate: str, *, flag_format: object = None) -> list[str]:
        """Return validator-worthy variants implied by policy, not by prompting."""

        text = str(candidate or "").strip()
        expected_prefix = cls._expected_prefix(flag_format)
        if not text or not expected_prefix:
            return []

        variants: list[str] = []
        if bare_token_shape(text) and not flag_prefix_shape(text):
            rewritten = f"{expected_prefix}{{{text}}}"
            if cls.decision(rewritten, flag_format=flag_format).accepted:
                variants.append(rewritten)
        return variants

    @classmethod
    def derived_candidates_for_state(cls, state: "RunState", candidate: str) -> list[str]:
        challenge = state.metadata.get("challenge", {}) or {}
        return cls.derived_candidates(candidate, flag_format=challenge.get("flag_format"))

    @classmethod
    def validation_ready_candidates(cls, state: "RunState") -> list[FlagCandidate]:
        ready: list[FlagCandidate] = []
        for candidate in state.flag_candidates.values():
            if candidate.validated is False or candidate.rejected_reason:
                continue
            if cls.accepts_for_state(state, candidate.value):
                ready.append(candidate)
        return sorted(ready, key=lambda item: item.confidence, reverse=True)

    @classmethod
    def first_candidate_from_context(
        cls,
        state: "RunState",
        context: dict[str, Any],
        goal: str = "",
    ) -> str | None:
        grounded = {
            candidate.value
            for candidate in cls.validation_ready_candidates(state)
        }
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
                if text and text in grounded and cls.accepts_for_state(state, text):
                    return text

        from killchain_docker.reasoning.flag import extract_flag_candidates

        for candidate in extract_flag_candidates(goal, include_bare=False):
            if candidate in grounded and cls.accepts_for_state(state, candidate):
                return candidate
        return None

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


class TodoPolicy:
    """Normalize high-level todos and assign stable semantic families."""

    @classmethod
    def normalize(cls, todo: "PlannedTodo", state: "RunState") -> "PlannedTodo":
        context = todo.context
        challenge = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge.get("files", []) or [])
        goal_l = todo.goal.lower()
        cls._normalize_flag_format_context(context, challenge)

        family = cls.family_for(todo.goal, context)
        family = cls._normalize_artifact_target_context(todo, state, family)
        context["family"] = family

        if challenge_files and cls._goal_needs_files(goal_l):
            context.setdefault("files_root", DEFAULT_FILES_ROOT)
            context.setdefault("challenge_files", challenge_files)

        cls._apply_execution_closure_context(todo, context, family)

        candidate = CandidatePolicy.first_candidate_from_context(state, context, todo.goal)
        ready_candidates = CandidatePolicy.validation_ready_candidates(state)
        if candidate:
            context["candidate_flag"] = candidate
            todo.phase = TodoPhase.FLAG_VALIDATION
        elif todo.phase == TodoPhase.FLAG_VALIDATION and ready_candidates:
            context["candidate_flag"] = ready_candidates[0].value
            todo.phase = TodoPhase.FLAG_VALIDATION
        elif todo.phase == TodoPhase.FLAG_VALIDATION:
            todo.phase = TodoPhase.ANALYSIS

        if todo.phase == TodoPhase.EXPLOIT and cls._is_local_artifact_recovery(goal_l, context, family):
            todo.phase = TodoPhase.ANALYSIS

        if cls._is_compound_disassembly_and_exploit(todo.goal):
            todo.phase = TodoPhase.ANALYSIS
            context["family"] = "binary-analysis"
            context.pop("execution_closure", None)
            context["capability_hint"] = "shell.exec"
            context["dispatch_intent"] = {
                "profile": "binary_analysis",
                "required_capability": "shell.exec",
            }
            todo.goal = (
                "Extract precise binary algorithm evidence needed for the next "
                "decryption attempt."
            )
            todo.success_criteria = [
                "Capture the exact algorithm or loop evidence needed for a later script.",
            ]

        intent_payload = DispatchIntent.from_context(context).model_dump(
            mode="json",
            exclude_defaults=True,
        )
        intent_payload.pop("completion_contract", None)
        intent_payload.pop("repair_policy_id", None)
        context["dispatch_intent"] = intent_payload

        structural_key = cls.structural_key(todo)
        if structural_key:
            todo.dedupe_key = structural_key
        elif not todo.dedupe_key:
            todo.dedupe_key = cls.default_key(todo)
        return todo

    @staticmethod
    def _normalize_flag_format_context(
        context: dict[str, Any],
        challenge: dict[str, Any],
    ) -> None:
        expected_prefix = CandidatePolicy._expected_prefix(challenge.get("flag_format"))
        if expected_prefix:
            context["flag_format_prefix"] = f"{expected_prefix}{{"
            return
        context.pop("flag_format_prefix", None)

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
            "finding_id",
            "vulnerability_id",
            "credential_id",
            "session_id",
            "hypothesis_id",
            "evidence_id",
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
            "finding_ids",
            "vulnerability_ids",
            "credential_ids",
            "session_ids",
            "hypothesis_ids",
            "evidence_ids",
        ):
            value = context.get(key)
            if isinstance(value, list) and value:
                important.append(",".join(str(item) for item in value[:8]))
        return "todo:" + ":".join(important)

    @staticmethod
    def structural_key(todo: "PlannedTodo | TodoItem") -> str | None:
        context = todo.context or {}
        hint = str(context.get("capability_hint") or "").strip()
        path = TodoPolicy._context_path(context)
        if hint == "disk.extract" and path:
            return f"bootstrap:disk-extract:{path}"
        if hint in {"office.inspect", "png.inspect"} and path:
            return f"bootstrap:artifact-followup:{path}"
        if hint == "artifact.triage" and path and "/.autopentest_artifacts/" in path:
            return f"bootstrap:artifact-followup:{path}"
        return None

    @classmethod
    def _normalize_artifact_target_context(
        cls,
        todo: "PlannedTodo",
        state: "RunState",
        family: str,
    ) -> str:
        context = todo.context or {}
        goal_l = todo.goal.lower()
        if cls._looks_like_disk_extraction(goal_l):
            if todo.phase == TodoPhase.RECON:
                todo.phase = TodoPhase.ANALYSIS
            disk_artifacts = [
                artifact
                for artifact in state.artifacts.values()
                if cls._artifact_is_disk_image_like(artifact)
            ]
            if not cls._context_path(context) and len(disk_artifacts) == 1:
                cls._bind_artifact_target(context, disk_artifacts[0])
            if cls._context_path(context):
                context["capability_hint"] = "disk.extract"
            return "forensics-extract"

        if todo.phase not in {TodoPhase.ANALYSIS, TodoPhase.EXPLOIT}:
            return family
        path = cls._context_path(context)
        if path:
            artifact = cls._artifact_by_path(state, path)
            if artifact is not None and cls._capability_hint_targets_artifact(
                context.get("capability_hint"),
                artifact,
            ):
                context["capability_hint"] = cls._capability_for_artifact(artifact)
                if family in {"other", "source-review", "forensics-extract"}:
                    return "artifact-followup"
            return family

        mentioned = cls._unique_artifact_mentioned(goal_l, state)
        if mentioned is not None:
            cls._bind_artifact_target(context, mentioned)
            if cls._capability_hint_targets_artifact(
                context.get("capability_hint"),
                mentioned,
            ):
                context["capability_hint"] = cls._capability_for_artifact(mentioned)
            else:
                context.setdefault("capability_hint", cls._capability_for_artifact(mentioned))
            if family in {"other", "source-review", "forensics-extract"}:
                return "artifact-followup"
        return family

    @staticmethod
    def _artifact_by_path(state: "RunState", path: str) -> Any | None:
        target = str(path or "").strip()
        if not target:
            return None
        for artifact in state.artifacts.values():
            if str(getattr(artifact, "path", "") or "").strip() == target:
                return artifact
        return None

    @staticmethod
    def _capability_hint_is_abstract(value: object) -> bool:
        hint = str(value or "").strip().lower().replace("_", ".")
        return hint in {
            "",
            "analyze",
            "analysis",
            "artifact.analyze",
            "artifact.extract",
            "artifact.inspect",
            "artifact.parse",
            "disk.rawscan",
            "file.analyze",
            "forensics.analyze",
            "forensics.extract",
            "media.analyze",
            "media.inspect",
        }

    @staticmethod
    def _capability_hint_targets_artifact(value: object, artifact: Any) -> bool:
        """Return true when a target-bound hint should use artifact tooling."""

        if TodoPolicy._capability_hint_is_abstract(value):
            return True
        hint = str(value or "").strip().lower().replace("_", ".")
        canonical = TodoPolicy._capability_for_artifact(artifact)
        if canonical == "office.inspect":
            return hint in {
                "document.analyze",
                "document.extract",
                "document.inspect",
                "office.analyze",
                "office.extract",
                "openxml.extract",
                "ppt.extract",
                "pptx.extract",
                "presentation.extract",
            }
        if canonical == "png.inspect":
            return hint in {
                "image.analyze",
                "image.extract",
                "image.inspect",
                "png.analyze",
                "png.extract",
                "stego.analyze",
                "steganalysis",
            }
        if canonical == "media.scan":
            return hint in {
                "media.analyze",
                "media.extract",
                "media.inspect",
                "video.analyze",
                "video.extract",
            }
        return False

    @staticmethod
    def _bind_artifact_target(context: dict[str, Any], artifact: Any) -> None:
        artifact_id = str(getattr(artifact, "artifact_id", "") or "").strip()
        path = str(getattr(artifact, "path", "") or "").strip()
        if artifact_id:
            context.setdefault("artifact_id", artifact_id)
        if path:
            context.setdefault("artifact_path", path)
            context.setdefault("path", path)
            context.setdefault("files_root", DEFAULT_FILES_ROOT)

    @staticmethod
    def _looks_like_disk_extraction(goal_l: str) -> bool:
        return any(
            token in goal_l
            for token in (
                "disk image",
                "filesystem",
                "file system",
                "partition",
                "mbr",
                "boot sector",
                "embedded zip",
                "carve",
            )
        ) and any(
            token in goal_l
            for token in (
                "extract",
                "carve",
                "recover",
                "analyze",
                "analyse",
                "inspect",
            )
        )

    @staticmethod
    def _artifact_is_disk_image_like(artifact: Any) -> bool:
        return facts_from_artifact(artifact).is_disk_image

    @staticmethod
    def _unique_artifact_mentioned(goal_l: str, state: "RunState") -> Any | None:
        matches: list[Any] = []
        for artifact in state.artifacts.values():
            path = str(getattr(artifact, "path", "") or "").strip()
            if not path:
                continue
            basename = path.rsplit("/", 1)[-1].lower()
            if basename and re.search(rf"(?<![A-Za-z0-9_.-]){re.escape(basename)}(?![A-Za-z0-9_.-])", goal_l):
                matches.append(artifact)
        if len(matches) != 1:
            return None
        return matches[0]

    @staticmethod
    def _capability_for_artifact(artifact: Any) -> str:
        return artifact_followup_capability(artifact)

    @staticmethod
    def _context_path(context: dict[str, Any]) -> str:
        for key in ("artifact_path", "path", "file_path"):
            value = context.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        paths = context.get("paths")
        if isinstance(paths, list) and paths:
            first = paths[0]
            if isinstance(first, str) and first.strip():
                return first.strip()
        return ""

    @staticmethod
    def family_for(goal: str, context: dict[str, Any] | None = None) -> str:
        context = context or {}
        explicit = str(context.get("family") or "").strip()
        if explicit and explicit != "other":
            return explicit
        derived = TodoPolicy._derive_family_from_goal(goal)
        if derived != "other":
            return derived
        return explicit or "other"

    @staticmethod
    def _derive_family_from_goal(goal: str) -> str:
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
            token in text
            for token in ("algorithm", "analy", "inspect", "recover")
        ):
            return "binary-analysis"
        if any(token in text for token in ("decrypt", "keystream", "known-plaintext", "lfsr", "cipher", "xor")):
            return "crypto-decrypt"
        if "flag" in text and any(token in text for token in ("recover", "validate", "candidate")):
            return "flag-recovery"
        if any(token in text for token in ("inventory", "classify", "triage")):
            return "artifact-inventory"
        if (
            any(token in text for token in ("list", "enumerate", "inspect", "identify"))
            and any(token in text for token in ("file", "files", "artifact", "artifacts", "directory"))
        ):
            return "artifact-inventory"
        if "scope" in text or "recon" in text:
            return "recon"
        return "other"

    @staticmethod
    def _is_local_artifact_recovery(goal_l: str, context: dict[str, Any], family: str) -> bool:
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

    @staticmethod
    def _apply_execution_closure_context(
        todo: "PlannedTodo",
        context: dict[str, Any],
        family: str,
    ) -> None:
        if todo.phase not in {TodoPhase.ANALYSIS, TodoPhase.EXPLOIT}:
            return
        if family not in {
            "algorithm-verification",
            "crypto-decrypt",
            "flag-recovery",
            "binary-analysis",
        }:
            return

        text = " ".join(
            [
                todo.goal,
                " ".join(str(item) for item in todo.success_criteria),
                " ".join(str(item) for item in todo.constraints),
            ]
        ).lower()
        if not any(
            token in text
            for token in (
                "algorithm",
                "cipher",
                "decode",
                "decrypt",
                "derive",
                "flag",
                "keystream",
                "lfsr",
                "recover",
                "reference",
                "source",
            )
        ):
            return

        context.setdefault(
            "execution_closure",
            True,
        )
        context.setdefault("capability_hint", "script.exec")
        raw_intent = context.get("dispatch_intent")
        intent = dict(raw_intent) if isinstance(raw_intent, dict) else {}
        intent["profile"] = intent.get("profile") or "execution_closure"
        intent["required_capability"] = intent.get("required_capability") or "script.exec"
        intent.pop("completion_contract", None)
        intent.pop("repair_policy_id", None)
        context["dispatch_intent"] = intent

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

    FAILURE_COOLDOWN_THRESHOLD = 3
    MAX_FAMILY_ATTEMPTS = 10  # raised from 6; iterative families are exempt below
    MAX_FLAG_VALIDATION_ATTEMPTS = 3  # flag-validation is cheap; cap early to avoid loops
    CONSECUTIVE_FAILURE_CAP = 5  # Hard pivot after 5 consecutive failures without new evidence

    # Families that are inherently iterative — apply cooldown but no hard cap.
    _UNCAPPED_FAMILIES = frozenset({
        "algorithm-verification",
        "artifact-inventory",
        "flag-recovery",
        "recon",
        "crypto-decrypt",
        "binary-analysis",
    })

    @classmethod
    def allows(cls, todo: "PlannedTodo", state: "RunState") -> tuple[bool, str]:
        family = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))

        # Hard block: forced pivot bans specific families
        forced_pivot = state.metadata.get("forced_pivot")
        if isinstance(forced_pivot, dict):
            banned = {str(item) for item in (forced_pivot.get("banned_families") or [])}
            blocked = sorted(cls._todo_family_candidates(todo, family) & banned)
            if blocked:
                return False, (
                    f"family {blocked[0]!r} is BANNED by forced pivot "
                    f"#{forced_pivot.get('pivot_number', '?')}"
                )

        total, failed = cls._family_counts(state, family)

        # Flag-validation: cap per-candidate, not per-family.
        # Different candidates must always get a chance; only block repeated
        # validation of the *same* candidate value.
        if family == "flag-validation":
            candidate_val = str(todo.context.get("candidate_flag") or "").strip()
            if candidate_val:
                same_candidate_count = sum(
                    1 for t in state.todos
                    if str(t.context.get("family") or TodoPolicy.family_for(t.goal, t.context)) == family
                    and str(t.context.get("candidate_flag") or "").strip() == candidate_val
                )
                if same_candidate_count >= cls.MAX_FLAG_VALIDATION_ATTEMPTS:
                    return False, (
                        f"candidate {candidate_val!r} already validated "
                        f"{same_candidate_count} time(s); "
                        "propose a different candidate or set stop_run=true"
                    )
                return True, ""
            elif total >= cls.MAX_FLAG_VALIDATION_ATTEMPTS:
                return False, (
                    f"family {family!r} hit validation cap ({total} attempts) "
                    "without a concrete candidate"
                )

        if family in cls._UNCAPPED_FAMILIES:
            # Check consecutive failures without progress
            consecutive = cls._consecutive_failures_without_evidence(state, family)
            if consecutive >= cls.CONSECUTIVE_FAILURE_CAP:
                return False, f"family {family!r} bankrupt: {consecutive} consecutive failures without new evidence"
            # Cooldown with tighter Jaccard after many failures
            if failed < cls.FAILURE_COOLDOWN_THRESHOLD:
                return True, ""
            if cls._has_new_novelty(todo, state, family):
                return True, ""
            return False, f"family {family!r} is in cooldown after {failed} failed/partial attempt(s)"
        if total >= cls.MAX_FAMILY_ATTEMPTS:
            if cls._is_evidence_triggered_artifact_followup(todo, state, family):
                return True, ""
            return False, f"family {family!r} hit hard cap ({total} total attempts)"
        if failed < cls.FAILURE_COOLDOWN_THRESHOLD:
            return True, ""
        if cls._has_new_novelty(todo, state, family):
            return True, ""
        return False, f"family {family!r} is in cooldown after {failed} failed/partial attempt(s)"

    @staticmethod
    def _is_evidence_triggered_artifact_followup(
        todo: "PlannedTodo",
        state: "RunState",
        family: str,
    ) -> bool:
        if family != "artifact-followup":
            return False
        context = todo.context or {}
        capability = str(context.get("capability_hint") or "").strip()
        if capability not in {"artifact.triage", "media.scan", "office.inspect", "png.inspect"}:
            return False
        if not TodoPolicy._context_path(context):
            return False
        return ContextRefPolicy.refs_existing(
            context,
            state.evidence,
            "evidence_id",
            "evidence_ids",
        )

    @staticmethod
    def _todo_family_candidates(todo: "PlannedTodo", family: str) -> set[str]:
        candidates = {family}
        context = todo.context or {}
        text = " ".join(
            [
                todo.goal,
                " ".join(str(item) for item in todo.success_criteria),
                " ".join(str(item) for item in todo.constraints),
                " ".join(
                    str(context.get(key) or "")
                    for key in ("capability_hint", "tool", "tool_name")
                ),
            ]
        )
        derived = TodoPolicy._derive_family_from_goal(text)
        if derived != "other":
            candidates.add(derived)
        return candidates

    @classmethod
    def _family_counts(cls, state: "RunState", family: str) -> tuple[int, int]:
        total = 0
        failed = 0
        for todo in state.todos:
            current = str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context))
            if current == family:
                total += 1
                if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
                    failed += 1
        return total, failed

    @classmethod
    def _consecutive_failures_without_evidence(cls, state: "RunState", family: str) -> int:
        """Count consecutive failed/partial todos in a family from the tail, stopping at any success with real progress."""
        family_todos = [
            todo for todo in state.todos
            if str(todo.context.get("family") or TodoPolicy.family_for(todo.goal, todo.context)) == family
        ]
        consecutive = 0
        for todo in reversed(family_todos):
            if todo.status in {TodoStatus.FAILED, TodoStatus.PARTIAL, TodoStatus.BLOCKED}:
                consecutive += 1
            elif todo.status == TodoStatus.COMPLETED:
                # Only break if this completion actually produced meaningful progress
                if todo.result_summary and "0 flag candidate" in todo.result_summary.lower():
                    consecutive += 1  # Useless completion — count as failure
                else:
                    break
            else:
                # PENDING or IN_PROGRESS — skip, don't break the streak
                continue
        return consecutive

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

    @staticmethod
    def _has_new_novelty(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
        novelty = str(todo.context.get("novelty_key") or "").strip()
        if novelty:
            previous = {
                str(item.context.get("novelty_key") or "").strip()
                for item in state.todos
                if str(item.context.get("family") or TodoPolicy.family_for(item.goal, item.context)) == family
            }
            if novelty in previous and not ProgressPolicy._has_new_state_refs(todo, state, family):
                return False
        return ProgressPolicy._has_new_state_refs(todo, state, family)

    @staticmethod
    def _has_new_state_refs(todo: "PlannedTodo", state: "RunState", family: str) -> bool:
        return (
            ProgressPolicy._has_new_existing_refs(
                todo,
                state.evidence,
                state,
                family,
                "evidence_ids",
            )
            or ProgressPolicy._has_new_existing_refs(
                todo,
                state.hypotheses,
                state,
                family,
                "hypothesis_id",
                "hypothesis_ids",
            )
        )

    @staticmethod
    def _has_new_existing_refs(
        todo: "PlannedTodo",
        records: dict[str, Any],
        state: "RunState",
        family: str,
        *keys: str,
    ) -> bool:
        refs = ContextRefPolicy.values(todo.context, *keys)
        if not refs or not refs.issubset(records.keys()):
            return False
        previous_refs: set[str] = set()
        for item in state.todos:
            current = str(item.context.get("family") or TodoPolicy.family_for(item.goal, item.context))
            if current != family:
                continue
            previous_refs.update(ContextRefPolicy.values(item.context, *keys))
        return not refs.issubset(previous_refs)


class RoundOutcomePolicy:
    """Classify worker round results before the orchestrator mutates control flow."""

    @staticmethod
    def has_observation_text(payload: dict[str, object]) -> bool:
        for key in ("stdout", "stderr", "output_text", "raw_log"):
            if str(payload.get(key) or "").strip():
                return True
        return False

    @classmethod
    def is_hollow_result(cls, result: WorkerResult) -> bool:
        """Detect successful results that produced no state signal or observation."""
        if not result.success or result.partial or result.solved:
            return False
        delta = result.state_delta
        if delta and (
            delta.flag_candidates
            or delta.artifacts
            or delta.endpoints
            or delta.routes
            or delta.hypotheses
            or delta.vulnerabilities
            or delta.exploit_attempts
            or delta.sessions
        ):
            return False
        ctx = result.output_context or {}
        if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
            return False
        if cls.has_observation_text(ctx):
            return False
        for evidence in result.evidence_updates:
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            evidence_ctx = extracted.get("output_context")
            if isinstance(evidence_ctx, dict) and cls.has_observation_text(evidence_ctx):
                return False
            evidence_result = evidence.result if isinstance(evidence.result, dict) else {}
            if cls.has_observation_text(evidence_result):
                return False
        if result.result_quality:
            return False
        if result.finding_updates or result.credential_updates:
            return False
        return True

    @staticmethod
    def had_meaningful_progress(results: list[WorkerResult]) -> bool:
        """Return true when a round emitted durable progress signals."""
        for result in results:
            delta = result.state_delta
            if result.partial:
                if delta and (
                    delta.flag_candidates
                    or delta.artifacts
                    or delta.endpoints
                    or delta.routes
                    or delta.hypotheses
                    or delta.vulnerabilities
                    or delta.exploit_attempts
                    or delta.sessions
                ):
                    return True
                if result.finding_updates or result.credential_updates:
                    return True
                ctx = result.output_context or {}
                if ctx.get("near_miss_candidates") or ctx.get("flag_candidates"):
                    return True
                if RoundOutcomePolicy.has_observation_text(ctx):
                    return True
                for evidence in result.evidence_updates:
                    extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
                    evidence_ctx = extracted.get("output_context")
                    if isinstance(evidence_ctx, dict) and RoundOutcomePolicy.has_observation_text(evidence_ctx):
                        return True
                    evidence_result = evidence.result if isinstance(evidence.result, dict) else {}
                    if RoundOutcomePolicy.has_observation_text(evidence_result):
                        return True
            if not result.success:
                continue
            if delta and (
                delta.flag_candidates
                or delta.vulnerabilities
                or delta.sessions
                or delta.exploit_attempts
            ):
                return True
            if result.finding_updates or result.credential_updates:
                return True
            ctx = result.output_context or {}
            if ctx.get("near_miss_candidates"):
                return True
        return False

    @staticmethod
    def forced_pivot_directive(
        state: "RunState",
        *,
        pivot_number: int,
        cycle: int,
        threshold: int,
    ) -> dict[str, object]:
        """Build the metadata directive used to force a strategy pivot."""
        snapshot = ProgressPolicy.stagnation_snapshot(state)
        failed_counts = snapshot.get("failed_or_partial_family_counts", {})
        banned_families = sorted(
            family for family, count in failed_counts.items()
            if count >= ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD
        )

        family_counts = snapshot.get("family_counts", {})
        if family_counts:
            top_family = max(family_counts, key=lambda family: family_counts[family])
            if top_family not in banned_families and family_counts[top_family] >= 3:
                banned_families.append(top_family)

        return {
            "pivot_number": pivot_number,
            "triggered_at_cycle": cycle,
            "banned_families": banned_families,
            "instruction": (
                f"FORCED PIVOT #{pivot_number}: The run has spent "
                f"{threshold} consecutive rounds without producing "
                f"a valid flag candidate. The following approach families are NOW BANNED "
                f"and must NOT be re-attempted: {banned_families}. "
                "You MUST propose a fundamentally different attack vector: "
                "different algorithm, different tool, different attack surface, "
                "or different interpretation of the challenge. "
                "If no alternative exists, set stop_run=true."
            ),
        }


class RagPolicy:
    """Annotate retrieved writeups when they appear to mislead planning.

    Earlier versions of this policy fully hid the writeups once a related
    family failed twice.  In practice that punished the planner: the writeup
    is the planner's only outside knowledge for crypto/forensics challenges,
    and removing it caused the run to stall with empty proposals.  The
    revised policy never suppresses; it only tags the writeup as
    ``possibly_misleading`` so the planner prompt can react accordingly.
    """

    @staticmethod
    def annotate(state: "RunState") -> None:
        rag = state.metadata.setdefault("rag", {})
        if not isinstance(rag, dict):
            return
        snapshot = ProgressPolicy.stagnation_snapshot(state)
        failed = snapshot.get("failed_or_partial_family_counts", {})
        stalled_families = sorted(
            family for family, count in (failed or {}).items()
            if isinstance(count, int) and count >= ProgressPolicy.FAILURE_COOLDOWN_THRESHOLD
        )
        if stalled_families:
            rag["policy"] = "possibly_misleading"
            rag["stalled_families"] = stalled_families
        else:
            rag.pop("stalled_families", None)
            if rag.get("policy") == "possibly_misleading":
                rag.pop("policy", None)
