"""Annotate the knowledge cache when retrieved priors look misleading."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.orchestrator.progress.families import stagnation_snapshot
from killchain_docker.orchestrator.progress.limits import FAILURE_COOLDOWN_THRESHOLD
from killchain_docker.state.metadata import RunMetadataStore

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class KnowledgePolicy:
    """Tag knowledge augmentation when stagnation suggests bad priors."""

    @staticmethod
    def annotate(state: "RunState") -> None:
        cache = RunMetadataStore(state).mutable_knowledge()
        if cache is None:
            return
        snapshot = stagnation_snapshot(state)
        failed = snapshot.get("failed_or_partial_family_counts", {})
        stalled_families = sorted(
            family
            for family, count in (failed or {}).items()
            if isinstance(count, int) and count >= FAILURE_COOLDOWN_THRESHOLD
        )
        if stalled_families:
            cache["policy"] = "possibly_misleading"
            cache["stalled_families"] = stalled_families
        else:
            cache.pop("stalled_families", None)
            if cache.get("policy") == "possibly_misleading":
                cache.pop("policy", None)
