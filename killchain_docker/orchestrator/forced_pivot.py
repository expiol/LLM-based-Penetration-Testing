"""Forced strategy pivot directives for stagnant runs."""

from __future__ import annotations

from killchain_docker.orchestrator.progress.families import stagnation_snapshot
from killchain_docker.orchestrator.progress.limits import FAILURE_COOLDOWN_THRESHOLD
from killchain_docker.state.run_state import RunState


_PIVOT_FALLBACK_EXCLUDED_FAMILIES = frozenset(
    {"artifact-inventory", "artifact-followup", "recon", "flag-validation"}
)


def forced_pivot_directive(
    state: RunState, *, pivot_number: int, cycle: int, threshold: int
) -> dict[str, object]:
    """Build the metadata directive used to force a strategy pivot."""
    snapshot = stagnation_snapshot(state)
    failed_counts = snapshot.get("failed_or_partial_family_counts", {})
    banned_families = sorted(
        (
            family
            for family, count in failed_counts.items()
            if count >= FAILURE_COOLDOWN_THRESHOLD
        )
    )
    family_counts = snapshot.get("family_counts", {})
    if family_counts:
        top_family = max(family_counts, key=lambda family: family_counts[family])
        if top_family not in banned_families and family_counts[top_family] >= 3:
            banned_families.append(top_family)
    if not banned_families:
        fallback_family = _fallback_banned_family(family_counts)
        if fallback_family is not None:
            banned_families.append(fallback_family)
    return {
        "pivot_number": pivot_number,
        "triggered_at_cycle": cycle,
        "banned_families": banned_families,
        "instruction": f"FORCED PIVOT #{pivot_number}: The run has spent {threshold} consecutive rounds without producing a valid flag candidate. The following approach families are NOW BANNED and must NOT be re-attempted: {banned_families}. You MUST propose a fundamentally different attack vector: different algorithm, different tool, different attack surface, or different interpretation of the challenge. If no alternative exists, set stop_run=true.",
    }


def _fallback_banned_family(family_counts: object) -> str | None:
    if not isinstance(family_counts, dict):
        return None
    eligible: list[tuple[str, int]] = []
    for family, count in family_counts.items():
        name = str(family)
        try:
            total = int(count)
        except (TypeError, ValueError):
            continue
        if name in _PIVOT_FALLBACK_EXCLUDED_FAMILIES:
            continue
        if total < 2:
            continue
        eligible.append((name, total))
    if not eligible:
        return None
    eligible.sort(key=lambda item: (-item[1], item[0]))
    return eligible[0][0]
