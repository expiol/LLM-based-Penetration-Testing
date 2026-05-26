"""Typed state-delta application."""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.state.artifact_store import ArtifactFactStore
from killchain_docker.state.candidate_facts import FlagCandidateStore
from killchain_docker.state.execution_facts import ExecutionFactStore
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.state.domain import FlagCandidate, StateDelta

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class StateDeltaApplier:
    """Applies typed facts from one worker or tool result."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.artifacts = ArtifactFactStore(state)
        self.candidates = FlagCandidateStore(state)
        self.execution_facts = ExecutionFactStore(state)
        self.journal = RunJournal(state)
        self.maintenance = RunStateMaintenance(state)

    def apply(self, delta: StateDelta) -> None:
        for artifact in delta.artifacts:
            self.artifacts.artifact(artifact, touch=False)
        for endpoint in delta.endpoints:
            self.execution_facts.endpoint(endpoint, touch=False)
        for route in delta.routes:
            self.execution_facts.route(route, touch=False)
        for candidate in delta.flag_candidates:
            self._apply_flag_candidate(candidate)
        for hypothesis in delta.hypotheses:
            self.execution_facts.hypothesis(hypothesis, touch=False)
        for vulnerability in delta.vulnerabilities:
            self.execution_facts.vulnerability(vulnerability, touch=False)
        for attempt in delta.exploit_attempts:
            self.execution_facts.exploit_attempt(attempt, touch=False)
        for session in delta.sessions:
            self.execution_facts.session(session, touch=False)
        self.maintenance.touch()

    def _apply_flag_candidate(self, candidate: FlagCandidate) -> None:
        from killchain_docker.orchestrator.candidate_policy import CandidatePolicy

        derived_values: list[str] = []
        decision = CandidatePolicy.decision_for_state(self.state, candidate.value)
        rejection_reason = candidate.rejected_reason
        if not decision.accepted:
            rejection_reason = decision.reason
            derived_values = CandidatePolicy.derived_candidates_for_state(
                self.state, candidate.value
            )
        elif candidate.validated is not True and (not rejection_reason):
            rejection_reason = self.journal.rejected_flag_reason(candidate.value)
        if candidate.validated is False and (not rejection_reason):
            rejection_reason = "candidate_validation_failed"
        if rejection_reason:
            self._reject_flag_candidate(candidate, rejection_reason)
            for derived_value in derived_values:
                if self.journal.rejected_flag_reason(derived_value):
                    continue
                derived = FlagCandidate(
                    value=derived_value,
                    source=f"{candidate.source or 'unknown'}:policy-derived",
                    confidence=max(0.1, min(candidate.confidence, 0.45)),
                    evidence_refs=list(candidate.evidence_refs),
                    metadata={
                        **dict(candidate.metadata),
                        "derived_from_rejected_candidate": candidate.value,
                        "derivation": "expected_prefix_rewrite",
                    },
                )
                if CandidatePolicy.decision_for_state(
                    self.state, derived.value
                ).accepted:
                    self.candidates.flag_candidate(derived, touch=False)
            return
        self.candidates.flag_candidate(candidate, touch=False)

    def _reject_flag_candidate(self, candidate: FlagCandidate, reason: str) -> None:
        self.journal.rejected_flag_candidate(
            value=candidate.value,
            reason=reason,
            source=candidate.source,
            evidence_refs=candidate.evidence_refs,
        )
        self.candidates.remove_by_value(candidate.value, touch=False)
        self.journal.orchestration_note(
            f"Rejected flag candidate from {candidate.source or 'unknown'}: {reason}"
        )
