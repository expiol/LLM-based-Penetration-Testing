"""Solver result parsing.

Takes the executor outcome plus the LLM guidance and produces a clean
:class:`SolverFlagSet`.  Filters placeholder flags, deduplicates, and
optionally cleans near-miss candidates whose flag-shaped output had
non-printable bytes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from nyuctf_mutil_killchain.agents._helpers.flag import extract_flag_candidates
from nyuctf_mutil_killchain.agents._helpers.strings import merge_unique_strings
from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.executor import SolverExecutionOutcome
from nyuctf_mutil_killchain.state.task_factory import is_validatable_flag_candidate


_PLACEHOLDER_FLAGS = frozenset({
    "flag{not_found}", "flag{test}", "flag{test_placeholder}",
    "flag{manual_review_required}", "flag{placeholder}", "flag{todo}",
    "key{not_found}", "key{test}", "key{placeholder}",
    "flag{unknown}", "flag{example}", "key{unknown}",
    "flag{notfound}", "flag{not found}", "flag{none}",
})

# Patterns that match obvious placeholder *bodies*.  IMPORTANT: keep this list
# tight - patterns like ``test\d*`` would falsely flag real flags such as
# ``flag{test123}`` (which is the literal flag body of the CSAW 'stfu'
# challenge).  Only literal placeholder words go here, no digit-suffix or
# token-prefix wildcards.
_PLACEHOLDER_BODY_PATTERN = re.compile(
    r"^(not[_\s]?found|placeholder|manual[_\s]?review[_\s]?required"
    r"|todo|unknown|example|none|n/a|null|undefined|insert[_\s]?flag[_\s]?here"
    r"|your[_\s]?flag[_\s]?here|flag[_\s]?goes[_\s]?here|replace[_\s]?me)$",
    re.IGNORECASE,
)

_NEAR_MISS_CLEAN_RE = re.compile(r"[^\x20-\x7e]")
_STRUCTURED_FLAG_PATTERN = re.compile(r"^[A-Za-z0-9_]{2,}\{[ -~]{4,200}\}$")

def _harvest_bare_token_candidates(stdout: str, *, max_take: int = 3) -> list[str]:
    """Pull single-token candidates from the tail of stdout.

    Used only when the prefix-shaped extractor returned nothing.  Each
    candidate must pass :func:`is_validatable_flag_candidate` as a bare
    token, which already rejects Python exception names and common
    "give-up" sentinels.  Stderr is never scanned because solvers print
    debug logs and source echoes there.
    """
    if not stdout:
        return []
    out: list[str] = []
    raw_lines = stdout.replace("\r\n", "\n").split("\n")
    tail = [ln.strip() for ln in raw_lines if ln.strip()][-20:]
    for line in reversed(tail):
        if not is_validatable_flag_candidate(line):
            continue
        if line in out:
            continue
        out.append(line)
        if len(out) >= max_take:
            break
    return out


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
        # ``Real flag`` for retry-control purposes: anything that survived the
        # validatable-shape filter (canonical ``prefix{body}`` OR a clean
        # bare-token).  We accept both since the validation worker will resolve
        # correctness via equality against ``expected_flag`` in benchmark mode.
        return any(is_validatable_flag_candidate(c) for c in self.flag_candidates)


class SolverResultParser:
    """Combine guidance + outcome into a clean flag set.

    Extracts flag candidates from THREE sources, with prefix{body}-shaped
    matches preferred over plaintext-tail fallbacks:

    1. Plugin-emitted flag_candidates from output_context (already filtered).
    2. LLM-supplied grounded_flag_candidates from SolverCodeGuidance.
    3. Hex/base64/ROT13 decoded substrings of the solver's stdout/stderr -
       crucial because LLM-written solvers often print the flag as hex
       (e.g. ``[*] Encryption: 666c61677b...``) and the plugin's plain regex
       cannot see through that encoding.
    """

    def extract(
        self,
        outcome: SolverExecutionOutcome,
        guidance: SolverCodeGuidance,
        *,
        limit: int = 6,
    ) -> SolverFlagSet:
        decoded_from_streams = extract_flag_candidates(
            outcome.stdout,
            outcome.stderr,
        )

        plugin_candidates = list(outcome.output_context.get("flag_candidates") or [])
        merged = merge_unique_strings(
            decoded_from_streams,
            plugin_candidates,
            list(guidance.grounded_flag_candidates),
            limit=limit,
        )

        # Bare-token fallback (NYU non-prefix flags like
        # ``STFU_THIS_CHALLENGE_...``).  Only kicks in when nothing prefix-shaped
        # made it through, so it never competes with real ``flag{...}`` matches.
        if not merged:
            bare_tokens = _harvest_bare_token_candidates(outcome.stdout)
            merged = merge_unique_strings(bare_tokens, limit=limit)

        # Final gate: drop placeholders AND anything that fails the canonical
        # flag-shape filter.  Defence in depth — even though earlier producers
        # apply their own filters, a stale call site (or a non-solver_execution
        # plugin source carried in via guidance.grounded_flag_candidates) could
        # still smuggle junk through.  We DO NOT want to forward those: the
        # downstream flag-validate task factory filters them out anyway, but
        # forwarding the junk pollutes `flag_candidates` in finding metadata,
        # which the planner reads back as "candidate flags worth retrying".
        flag_candidates = [
            c for c in merged
            if not is_placeholder_flag(c) and is_validatable_flag_candidate(c)
        ]

        near_miss_raw = outcome.near_miss_candidates
        cleaned_near_miss: list[str] = []
        if not flag_candidates and near_miss_raw:
            cleaned_near_miss = clean_near_miss_candidates(near_miss_raw)

        return SolverFlagSet(
            flag_candidates=flag_candidates,
            cleaned_near_miss=cleaned_near_miss,
            near_miss_raw=near_miss_raw,
        )
