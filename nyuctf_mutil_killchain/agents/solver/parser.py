"""Solver result parsing.

Takes the executor outcome plus the LLM guidance and produces a clean
:class:`SolverFlagSet`.  Filters placeholder flags, deduplicates, and
optionally cleans near-miss candidates whose flag-shaped output had
non-printable bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nyuctf_mutil_killchain.agents._helpers.strings import merge_unique_strings
from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.executor import SolverExecutionOutcome


_PLACEHOLDER_FLAGS = frozenset({
    "flag{not_found}", "flag{test}", "flag{test_placeholder}",
    "flag{manual_review_required}", "flag{placeholder}", "flag{todo}",
    "key{not_found}", "key{test}", "key{placeholder}",
    "flag{unknown}", "flag{example}", "key{unknown}",
    "flag{notfound}", "flag{not found}", "flag{none}",
})

_PLACEHOLDER_BODY_PATTERN = re.compile(
    r"^(not[_\s]?found|test[_\s]?\d*|placeholder|manual[_\s]?review[_\s]?required"
    r"|todo|unknown|example|none|n/a|null|undefined|insert[_\s]?flag[_\s]?here"
    r"|your[_\s]?flag[_\s]?here|flag[_\s]?goes[_\s]?here|replace[_\s]?me)$",
    re.IGNORECASE,
)

_NEAR_MISS_CLEAN_RE = re.compile(r"[^\x20-\x7e]")


def is_placeholder_flag(candidate: str) -> bool:
    """Return True when *candidate* is an obvious LLM-fabricated placeholder."""
    cleaned = candidate.lower().strip()
    if cleaned in _PLACEHOLDER_FLAGS:
        return True
    _, _, rest = cleaned.partition("{")
    if rest and rest.endswith("}"):
        body = rest[:-1].strip()
        if _PLACEHOLDER_BODY_PATTERN.match(body):
            return True
    return False


def clean_near_miss_candidates(near_miss: list[str]) -> list[str]:
    """Strip non-printable bytes from near-miss strings and keep plausible shapes."""
    cleaned: list[str] = []
    for raw in near_miss:
        prefix, _, rest = raw.partition("{")
        if not rest or not rest.endswith("}"):
            continue
        body = rest[:-1]
        clean_body = _NEAR_MISS_CLEAN_RE.sub("", body)
        if len(clean_body) >= 4 and prefix.isalnum():
            candidate = f"{prefix}{{{clean_body}}}"
            if candidate not in cleaned:
                cleaned.append(candidate)
    return cleaned


@dataclass
class SolverFlagSet:
    """Flag candidates extracted from the solver run."""

    flag_candidates: list[str] = field(default_factory=list)
    cleaned_near_miss: list[str] = field(default_factory=list)
    near_miss_raw: list[str] = field(default_factory=list)

    @property
    def has_real_flag(self) -> bool:
        return bool(self.flag_candidates)


class SolverResultParser:
    """Combine guidance + outcome into a clean flag set."""

    def extract(
        self,
        outcome: SolverExecutionOutcome,
        guidance: SolverCodeGuidance,
        *,
        limit: int = 6,
    ) -> SolverFlagSet:
        merged = merge_unique_strings(
            outcome.output_context.get("flag_candidates") or [],
            list(guidance.grounded_flag_candidates),
            limit=limit,
        )
        flag_candidates = [c for c in merged if not is_placeholder_flag(c)]

        near_miss_raw = outcome.near_miss_candidates
        cleaned_near_miss: list[str] = []
        if not flag_candidates and near_miss_raw:
            cleaned_near_miss = clean_near_miss_candidates(near_miss_raw)

        return SolverFlagSet(
            flag_candidates=flag_candidates,
            cleaned_near_miss=cleaned_near_miss,
            near_miss_raw=near_miss_raw,
        )
