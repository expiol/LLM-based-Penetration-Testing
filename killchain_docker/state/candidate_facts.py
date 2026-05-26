"""Flag-candidate fact store."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.fact_merges import merge_flag_candidate
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import FlagCandidate
    from killchain_docker.state.run_state import RunState


class FlagCandidateStore:
    """Mutable store for accepted flag candidates."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def flag_candidate(self, candidate: "FlagCandidate", *, touch: bool = True) -> None:
        existing_id = next(
            (
                current_id
                for current_id, current in self.state.flag_candidates.items()
                if current.value == candidate.value
            ),
            None,
        )
        if existing_id is not None:
            merge_flag_candidate(self.state.flag_candidates[existing_id], candidate)
        else:
            self.state.flag_candidates[candidate.candidate_id] = candidate
        if touch:
            self.maintenance.touch()

    def remove_by_value(self, value: object, *, touch: bool = True) -> int:
        normalized = str(value or "").strip()
        if not normalized:
            return 0
        rejected_ids = [
            current_id
            for current_id, current in self.state.flag_candidates.items()
            if current.value == normalized
        ]
        for current_id in rejected_ids:
            del self.state.flag_candidates[current_id]
        if rejected_ids and touch:
            self.maintenance.touch()
        return len(rejected_ids)
