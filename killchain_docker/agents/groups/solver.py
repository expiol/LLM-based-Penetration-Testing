"""Solver worker group."""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.solver import SolverAgent

SOLVER_WORKERS: tuple[type, ...] = (SolverAgent,)


__all__ = [
    "SOLVER_WORKERS",
    "SolverAgent",
]
