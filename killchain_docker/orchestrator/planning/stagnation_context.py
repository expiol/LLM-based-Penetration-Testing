"""Planner-facing stagnation and pivot signals."""

from __future__ import annotations

from typing import Any

from killchain_docker.orchestrator.progress.families import (
    consecutive_failures_without_evidence,
    stagnation_snapshot,
)
from killchain_docker.orchestrator.progress.limits import CONSECUTIVE_FAILURE_CAP
from killchain_docker.orchestrator.todo.family import family_for
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.metadata import RunMetadataStore
from killchain_docker.state.planner_projection import PlannerStateProjection
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoStatus

_STAGNATION_GUIDANCE = (
    "These signals are PRESCRIPTIVE. If escalation_required or forced_pivot is "
    "present, you MUST comply: either set stop_run=true or propose a "
    "fundamentally different attack vector that does NOT belong to any banned "
    "family. Rephrasing the same strategy will be rejected by the pipeline."
)


def build_stagnation_signals(state: RunState) -> dict[str, Any]:
    report_projection = RunReportProjection(state)
    planner_projection = PlannerStateProjection(state)
    queue = TodoQueue(state)
    snapshot = stagnation_snapshot(state)
    cooldown_families = snapshot.get("cooldown_families", [])
    family_counts = queue.family_counts(_todo_family)
    family_examples = queue.family_examples(_todo_family, per_family=3)
    todo_status_counts = report_projection.todo_status_counts()
    base_signals = planner_projection.stagnation_base()
    repeated_families = [
        {
            "family": family,
            "count": count,
            "examples": family_examples.get(family, []),
        }
        for family, count in sorted(
            family_counts.items(), key=lambda item: (-item[1], item[0])
        )
        if count > 1 and family != "other"
    ][:6]
    signals: dict[str, Any] = {
        **base_signals,
        "progress_policy": snapshot,
        "family_attempt_counts": dict(family_counts),
        "todo_status_counts": todo_status_counts,
        "partial_todos": [
            {
                "todo_id": todo.todo_id,
                "goal": todo.goal[:160],
                "result_summary": todo.result_summary[:240],
                "partial_reason": (todo.error or "")[:160],
            }
            for todo in queue.recent_by_status({TodoStatus.PARTIAL}, limit=20)
        ],
        "failed_todos": [
            {
                "todo_id": todo.todo_id,
                "goal": todo.goal[:160],
                "error": (todo.error or "")[:180],
            }
            for todo in queue.recent_by_status({TodoStatus.FAILED}, limit=20)
        ],
        "open_todos": [
            {
                "todo_id": todo.todo_id,
                "phase": str(todo.phase),
                "goal": todo.goal[:160],
                "attempts": todo.attempts,
            }
            for todo in queue.recent_by_status(
                {TodoStatus.PENDING, TodoStatus.RUNNING}, limit=20
            )
        ],
        "repeated_todo_families": repeated_families,
        "guidance": _STAGNATION_GUIDANCE,
    }
    if cooldown_families:
        top = cooldown_families[0]
        count = family_counts.get(top, 0)
        signals["escalation_required"] = (
            f"Family {top!r} is in cooldown after {count} attempts. You MUST "
            "propose a fundamentally different approach (different algorithm, "
            "different tool, different attack vector). Do NOT rephrase the "
            "same strategy."
        )
    forced_pivot = RunMetadataStore(state).forced_pivot()
    if forced_pivot is not None:
        signals["forced_pivot"] = forced_pivot
    return signals


def pivot_summaries(state: RunState) -> list[dict[str, Any]]:
    queue = TodoQueue(state)
    summaries: list[dict[str, Any]] = []
    for family in queue.families(_pivot_family):
        consecutive = consecutive_failures_without_evidence(state, family)
        if consecutive < CONSECUTIVE_FAILURE_CAP:
            continue
        family_todos = queue.by_family(family, _pivot_family)
        summaries.append(
            {
                "family": family,
                "total_attempts": len(family_todos),
                "approaches_tried": [
                    {
                        "goal": todo.goal[:200],
                        "error": (todo.error or "")[:200],
                        "status": str(todo.status),
                    }
                    for todo in family_todos[-5:]
                ],
                "pivot_instruction": (
                    f"Family '{family}' is bankrupt after {consecutive} "
                    "consecutive failures. You MUST try a fundamentally "
                    "different approach: different algorithm, different tool, "
                    "different attack surface. Do NOT rephrase previous attempts."
                ),
            }
        )
    return summaries


def _todo_family(todo) -> str:
    return family_for(todo.goal, todo.context)


def _pivot_family(todo) -> str:
    return str(todo.context.get("family") or family_for(todo.goal, todo.context))
