"""Post-process worker results with derived candidates, hypotheses, and memory."""

from __future__ import annotations

from killchain_docker.memory.durable import DurableMemoryUpdate
from killchain_docker.orchestrator.candidate_policy import CandidatePolicy
from killchain_docker.reasoning.flag import encoding_cascade
from killchain_docker.state.domain import FlagCandidate, Hypothesis, StateDelta
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.results.memory import trusted_memory_updates
from killchain_docker.workers.results.recon import inject_recon_asset


def enrich_worker_result(
    result: WorkerResult,
    *,
    worker_name: str,
    task: TodoItem,
    state: RunState,
    last_bundle: ToolExecutionBundle,
    output_context: dict[str, object],
    hypotheses: list[Hypothesis],
    memory_updates: dict[str, str],
    durable_memory_updates: list[DurableMemoryUpdate] | None = None,
) -> WorkerResult:
    attach_cascade_candidates(result, state, last_bundle, output_context)
    attach_hypotheses(result, hypotheses)
    trusted_updates = trusted_memory_updates(task, result, memory_updates)
    if trusted_updates:
        result.memory_updates = trusted_updates
    if durable_memory_updates:
        result.durable_memory_updates = list(durable_memory_updates)
    if worker_name == "recon-worker":
        inject_recon_asset(task, state, result)
    return result


def attach_cascade_candidates(
    result: WorkerResult,
    state: RunState,
    last_bundle: ToolExecutionBundle,
    output_context: dict[str, object],
) -> None:
    if last_bundle.state_delta.flag_candidates:
        return
    cascade_candidates: list[FlagCandidate] = []
    near_misses = output_context.get("near_miss_candidates") or []
    for near_miss in near_misses[:3]:
        for transformed in encoding_cascade(str(near_miss)):
            if CandidatePolicy.accepts_for_state(state, transformed):
                cascade_candidates.append(
                    FlagCandidate(
                        value=transformed,
                        source="encoding_cascade",
                        confidence=0.2,
                    )
                )
    if cascade_candidates:
        existing = (
            list(result.state_delta.flag_candidates) if result.state_delta else []
        )
        result.state_delta = StateDelta(
            **{
                **result.state_delta.model_dump(),
                "flag_candidates": existing + cascade_candidates,
            }
        )


def attach_hypotheses(result: WorkerResult, hypotheses: list[Hypothesis]) -> None:
    if not hypotheses:
        return
    existing = list(result.state_delta.hypotheses) if result.state_delta else []
    result.state_delta = StateDelta(
        **{
            **result.state_delta.model_dump(),
            "hypotheses": existing + hypotheses,
        }
    )


__all__ = [
    "attach_cascade_candidates",
    "attach_hypotheses",
    "enrich_worker_result",
]
