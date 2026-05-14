"""Helpers for worker-to-planner signals."""

from __future__ import annotations

from collections.abc import Iterable

from killchain_docker.state import PlannerSignal, Task


def planner_signals_for_tasks(
    *,
    source_task: Task,
    worker_name: str,
    tasks: Iterable[Task],
    rationale: str = "Worker suggests this follow-up; planner decides whether to queue it.",
) -> list[PlannerSignal]:
    """Render task suggestions as planner signals without mutating the queue."""

    signals: list[PlannerSignal] = []
    for task in tasks:
        signals.append(
            PlannerSignal(
                source_task_id=source_task.task_id,
                worker_name=worker_name,
                summary=f"Suggested follow-up task: {task.title}",
                suggested_task_type=task.task_type,
                suggested_input_context=dict(task.input_context),
                rationale=rationale,
                metadata={"suggested_task": task.model_dump(mode="json")},
            )
        )
    return signals


__all__ = ["planner_signals_for_tasks"]
