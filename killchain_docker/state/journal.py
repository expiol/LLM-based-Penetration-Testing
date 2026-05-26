"""Append-only run journal adapters.

RunState is the durable data module. RunJournal owns the append and dedupe
policy for its log-like collections so orchestrator modules do not mutate
lists directly.
"""

from __future__ import annotations
from collections.abc import Iterable
from typing import TYPE_CHECKING
from killchain_docker.state.maintenance import RunStateMaintenance

if TYPE_CHECKING:
    from killchain_docker.state.domain import ExecutionRecord, RejectedFlagCandidate
    from killchain_docker.state.run_state import RunState
    from killchain_docker.state.todos import RouterRound, WorkerResult


class RunJournal:
    """Adapter for RunState's append-only notes, rounds, and execution logs."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.maintenance = RunStateMaintenance(state)

    def orchestration_note(self, note: object, *, touch: bool = True) -> str | None:
        text = self._clean_text(note)
        if not text:
            return None
        self.state.orchestration_notes.append(text)
        if touch:
            self.maintenance.touch()
        return text

    def orchestration_notes(
        self, notes: Iterable[object], *, touch: bool = True
    ) -> list[str]:
        appended = [text for note in notes if (text := self._clean_text(note))]
        if not appended:
            return []
        self.state.orchestration_notes.extend(appended)
        if touch:
            self.maintenance.touch()
        return appended

    def has_orchestration_note(self, note: object) -> bool:
        text = self._clean_text(note)
        if not text:
            return False
        return text in self.state.orchestration_notes

    def note(self, note: object, *, touch: bool = True) -> str | None:
        text = self._clean_text(note)
        if not text:
            return None
        self.state.notes.append(text)
        if touch:
            self.maintenance.touch()
        return text

    def notes(self, notes: Iterable[object], *, touch: bool = True) -> list[str]:
        appended = [text for note in notes if (text := self._clean_text(note))]
        if not appended:
            return []
        self.state.notes.extend(appended)
        if touch:
            self.maintenance.touch()
        return appended

    def worker_execution(
        self, result: "WorkerResult", *, touch: bool = True
    ) -> "ExecutionRecord":
        from killchain_docker.state.domain import ExecutionRecord

        record = ExecutionRecord(
            task_id=result.todo_id,
            worker_name=result.worker_name,
            success=result.success,
            summary=result.summary,
            error=result.error,
        )
        self.state.execution_log.append(record)
        if touch:
            self.maintenance.touch()
        return record

    def round(self, round_record: "RouterRound", *, touch: bool = True) -> None:
        self.state.rounds.append(round_record)
        if touch:
            self.maintenance.touch()

    def rejected_flag_candidate(
        self,
        *,
        value: str,
        reason: str,
        source: str | None = None,
        evidence_refs: list[str] | None = None,
        touch: bool = True,
    ) -> "RejectedFlagCandidate | None":
        from killchain_docker.state.domain import RejectedFlagCandidate

        normalized = str(value or "").strip()
        normalized_reason = str(reason or "").strip()
        if not normalized or not normalized_reason:
            return None
        refs = sorted(set(evidence_refs or []))
        existing = next(
            (
                item
                for item in self.state.rejected_flag_candidates
                if item.value == normalized and item.reason == normalized_reason
            ),
            None,
        )
        if existing is not None:
            merged_refs = sorted(set(existing.evidence_refs) | set(refs))
            changed = merged_refs != existing.evidence_refs
            existing.evidence_refs = merged_refs
            if changed and touch:
                self.maintenance.touch()
            return existing
        rejected = RejectedFlagCandidate(
            value=normalized,
            reason=normalized_reason,
            source=source,
            evidence_refs=refs,
        )
        self.state.rejected_flag_candidates.append(rejected)
        if touch:
            self.maintenance.touch()
        return rejected

    def rejected_flag_reason(self, value: object) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        for item in reversed(self.state.rejected_flag_candidates):
            if item.value == normalized:
                return item.reason or "previously_rejected"
        return None

    @staticmethod
    def _clean_text(value: object) -> str | None:
        text = str(value or "").strip()
        return text or None


__all__ = ["RunJournal"]
