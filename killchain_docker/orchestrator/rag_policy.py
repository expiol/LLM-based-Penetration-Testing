"""RAG metadata policy for planner context."""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.orchestrator.progress_families import stagnation_snapshot
from killchain_docker.orchestrator.progress_limits import FAILURE_COOLDOWN_THRESHOLD
from killchain_docker.state.metadata import RunMetadataStore

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class RagPolicy:
    """Annotate retrieved writeups when they appear to mislead planning."""

    @staticmethod
    def annotate(state: "RunState") -> None:
        rag = RunMetadataStore(state).mutable_rag()
        if rag is None:
            return
        snapshot = stagnation_snapshot(state)
        failed = snapshot.get("failed_or_partial_family_counts", {})
        stalled_families = sorted(
            (
                family
                for family, count in (failed or {}).items()
                if isinstance(count, int) and count >= FAILURE_COOLDOWN_THRESHOLD
            )
        )
        if stalled_families:
            rag["policy"] = "possibly_misleading"
            rag["stalled_families"] = stalled_families
        else:
            rag.pop("stalled_families", None)
            if rag.get("policy") == "possibly_misleading":
                rag.pop("policy", None)
