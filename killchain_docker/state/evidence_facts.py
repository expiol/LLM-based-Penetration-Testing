"""Evidence fact store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.fact_merges import merge_evidence
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import EvidenceRecord
    from killchain_docker.state.run_state import RunState


class EvidenceFactStore:
    """Mutable store for evidence records."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def evidence(self, evidence: "EvidenceRecord", *, touch: bool = True) -> None:
        if evidence.evidence_id in self.state.evidence:
            merge_evidence(self.state.evidence[evidence.evidence_id], evidence)
        else:
            self.state.evidence[evidence.evidence_id] = evidence
        if touch:
            self.maintenance.touch()
