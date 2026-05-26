"""Flag-candidate projection over durable run state."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class CandidateProjection:
    """Read-only candidate lists for policy and seed planning."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def validation_ready_records(self) -> list[object]:
        return list(self.state.flag_candidates.values())

    def rejected_records(self) -> list[object]:
        return list(self.state.rejected_flag_candidates)
