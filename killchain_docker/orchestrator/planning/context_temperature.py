"""Planner sampling temperature policy."""

from __future__ import annotations

from killchain_docker.orchestrator.progress.families import stagnation_snapshot
from killchain_docker.state.planner_projection import PlannerStateProjection
from killchain_docker.state.run_state import RunState


def compute_planner_temperature(state: RunState) -> float:
    snapshot = stagnation_snapshot(state)
    cooldown_count = len(snapshot.get("cooldown_families", []))
    rounds_without_flag = PlannerStateProjection(state).temperature_inputs()[
        "rounds_without_flag_candidate"
    ]
    if cooldown_count >= 2 or rounds_without_flag >= 8:
        return 0.6
    if cooldown_count >= 1 or rounds_without_flag >= 5:
        return 0.4
    return 0.2
