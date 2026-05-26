"""RunState maintenance store.

RunState is durable data. This module owns timestamp updates and bounded
collection retention so state models do not carry mutation policy.
"""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.state.common import utc_now
from killchain_docker.state.run_state import (
    EVIDENCE_DICT_LIMIT,
    EXECUTION_LOG_LIMIT,
    NOTES_LIMIT,
    ORCHESTRATION_NOTES_LIMIT,
    REJECTED_FLAG_CANDIDATE_LIMIT,
    TYPED_FACT_DICT_LIMIT,
)

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class RunStateMaintenance:
    """Mutable store for timestamps and bounded collection caps."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def touch(self) -> None:
        self.state.updated_at = utc_now()
        self.enforce_caps()

    def enforce_caps(self) -> None:
        state = self.state
        if len(state.execution_log) > EXECUTION_LOG_LIMIT:
            del state.execution_log[: len(state.execution_log) - EXECUTION_LOG_LIMIT]
        if len(state.notes) > NOTES_LIMIT:
            del state.notes[: len(state.notes) - NOTES_LIMIT]
        if len(state.orchestration_notes) > ORCHESTRATION_NOTES_LIMIT:
            del state.orchestration_notes[
                : len(state.orchestration_notes) - ORCHESTRATION_NOTES_LIMIT
            ]
        if len(state.evidence) > EVIDENCE_DICT_LIMIT:
            excess = len(state.evidence) - EVIDENCE_DICT_LIMIT
            for evidence_id in list(state.evidence.keys())[:excess]:
                del state.evidence[evidence_id]
        for fact_dict in (
            state.artifacts,
            state.endpoints,
            state.routes,
            state.flag_candidates,
            state.hypotheses,
            state.vulnerabilities,
            state.exploit_attempts,
            state.sessions,
        ):
            if len(fact_dict) <= TYPED_FACT_DICT_LIMIT:
                continue
            excess = len(fact_dict) - TYPED_FACT_DICT_LIMIT
            for key in list(fact_dict.keys())[:excess]:
                del fact_dict[key]
        if len(state.rejected_flag_candidates) > REJECTED_FLAG_CANDIDATE_LIMIT:
            del state.rejected_flag_candidates[
                : len(state.rejected_flag_candidates) - REJECTED_FLAG_CANDIDATE_LIMIT
            ]


__all__ = ["RunStateMaintenance"]
