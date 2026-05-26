"""Planning refresh result models."""

from __future__ import annotations

from dataclasses import dataclass

DETERMINISTIC_BACKLOG_SUMMARY = "planner skipped: ready todo backlog"


@dataclass(frozen=True)
class PlanningRefreshResult:
    """Summary of one planner-to-queue refresh."""

    summary: str
    proposed: int
    created: int
    created_ids: list[str]
    stop_run: bool = False
    deterministic: bool = False

    @property
    def deduped(self) -> int:
        return self.proposed - self.created


@dataclass(frozen=True)
class PlanningCycleResult:
    """Control-flow result after refreshing planner state for one cycle."""

    summary: str
    retry_cycle: bool = False
    halt_run: bool = False
