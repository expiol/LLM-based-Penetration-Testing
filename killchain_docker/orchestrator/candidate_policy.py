"""Flag candidate acceptance and selection policy."""

from __future__ import annotations
from dataclasses import dataclass
import re
from typing import TYPE_CHECKING, Any
from killchain_docker.state.constants import (
    bare_token_shape,
    flag_prefix_shape,
    looks_like_escaped_byte_candidate,
    validatable_flag_candidate,
)
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.domain import FlagCandidate

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState
_PREFIX_FROM_FORMAT_RE = re.compile("^([A-Za-z0-9_]+)(?:\\\\?\\{|\\{)")


@dataclass(frozen=True)
class CandidateDecision:
    accepted: bool
    reason: str = ""


class CandidatePolicy:
    """Validate and select flag candidates before they mutate run state."""

    @classmethod
    def decision_for_state(cls, state: "RunState", candidate: str) -> CandidateDecision:
        return cls.decision(
            candidate, flag_format=ChallengeProjection(state).flag_format()
        )

    @classmethod
    def accepts_for_state(cls, state: "RunState", candidate: str) -> bool:
        return cls.decision_for_state(state, candidate).accepted

    @classmethod
    def decision(
        cls, candidate: str, *, flag_format: object = None
    ) -> CandidateDecision:
        text = str(candidate or "").strip()
        if not text:
            return CandidateDecision(False, "empty_candidate")
        if looks_like_escaped_byte_candidate(text):
            return CandidateDecision(False, "escaped_byte_candidate")
        if not validatable_flag_candidate(text):
            return CandidateDecision(False, "invalid_candidate_shape")
        expected_prefix = cls._expected_prefix(flag_format)
        unknown_mode = not str(flag_format or "").strip()
        if bare_token_shape(text) and (not flag_prefix_shape(text)):
            if unknown_mode:
                return CandidateDecision(True)
            return CandidateDecision(False, "bare_token_for_prefix_challenge")
        if not flag_prefix_shape(text):
            return CandidateDecision(False, "invalid_prefix_candidate")
        if expected_prefix and (not text.startswith(expected_prefix + "{")):
            return CandidateDecision(False, "wrong_flag_prefix")
        return CandidateDecision(True)

    @classmethod
    def derived_candidates(
        cls, candidate: str, *, flag_format: object = None
    ) -> list[str]:
        """Return validator-worthy variants implied by policy, not by prompting."""
        text = str(candidate or "").strip()
        expected_prefix = cls._expected_prefix(flag_format)
        if not text or not expected_prefix:
            return []
        variants: list[str] = []
        if bare_token_shape(text) and (not flag_prefix_shape(text)):
            rewritten = f"{expected_prefix}{{{text}}}"
            if cls.decision(rewritten, flag_format=flag_format).accepted:
                variants.append(rewritten)
        return variants

    @classmethod
    def derived_candidates_for_state(
        cls, state: "RunState", candidate: str
    ) -> list[str]:
        return cls.derived_candidates(
            candidate, flag_format=ChallengeProjection(state).flag_format()
        )

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
        cls, state: "RunState", context: dict[str, Any], goal: str = ""
    ) -> str | None:
        grounded = {
            candidate.value for candidate in cls.validation_ready_candidates(state)
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
