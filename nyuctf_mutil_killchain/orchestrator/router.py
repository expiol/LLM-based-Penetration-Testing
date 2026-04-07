"""Worker routing strategies for task dispatch."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import BaseModel, Field

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.prompts import get_router_system_prompt
from nyuctf_mutil_killchain.state import GlobalState, Task


class WorkerRouteDecision(BaseModel):
    """Structured worker-selection result."""

    worker_name: str
    rationale: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class WorkerRouter(ABC):
    """Select the best worker among all compatible candidates."""

    @abstractmethod
    def route(
        self,
        *,
        task: Task,
        state: GlobalState,
        candidates: Sequence[WorkerAgent],
    ) -> WorkerRouteDecision:
        """Return a routed worker choice."""


class HeuristicWorkerRouter(WorkerRouter):
    """Deterministic routing fallback used when no LLM route is available."""

    def route(
        self,
        *,
        task: Task,
        state: GlobalState,
        candidates: Sequence[WorkerAgent],
    ) -> WorkerRouteDecision:
        if not candidates:
            raise ValueError("Worker router received no candidates.")

        preferred_workers = [
            str(value)
            for value in (
                list(task.metadata.get("preferred_workers") or [])
                + list(task.input_context.get("preferred_workers") or [])
            )
            if value
        ]

        ranked: list[tuple[int, int, WorkerAgent]] = []
        rejection_notes: list[str] = []
        for index, worker in enumerate(candidates):
            allowed, reason = worker.can_route_task(task, state)
            if not allowed:
                rejection_notes.append(f"{worker.name}: {reason}")
                continue

            score = worker.routing_score(task, state)
            if worker.name in preferred_workers:
                score += max(6, 18 - 3 * preferred_workers.index(worker.name))
            ranked.append((score, -index, worker))

        if ranked:
            score, _, worker = max(ranked, key=lambda item: (item[0], item[1]))
            rationale = (
                f"Heuristic router selected {worker.name} with score {score} "
                f"for task type {task.task_type}."
            )
            if rejection_notes:
                rationale += " Rejected candidates: " + "; ".join(rejection_notes[:3])
            return WorkerRouteDecision(worker_name=worker.name, rationale=rationale, confidence=0.35)

        worker = candidates[0]
        rationale = (
            f"Heuristic router fell back to the first compatible worker {worker.name} "
            f"because all candidates were filtered out."
        )
        if rejection_notes:
            rationale += " Filter reasons: " + "; ".join(rejection_notes[:3])
        return WorkerRouteDecision(worker_name=worker.name, rationale=rationale, confidence=0.1)


class LLMWorkerRouter(WorkerRouter):
    """LLM-assisted worker router with deterministic fallback."""

    def __init__(self, llm_client: LLMClient, fallback: WorkerRouter | None = None) -> None:
        self.llm_client = llm_client
        self.fallback = fallback or HeuristicWorkerRouter()

    def route(
        self,
        *,
        task: Task,
        state: GlobalState,
        candidates: Sequence[WorkerAgent],
    ) -> WorkerRouteDecision:
        if not candidates:
            raise ValueError("Worker router received no candidates.")
        if len(candidates) == 1:
            only = candidates[0]
            return WorkerRouteDecision(
                worker_name=only.name,
                rationale=f"Single compatible worker available: {only.name}.",
                confidence=1.0,
            )

        fallback_decision = self.fallback.route(task=task, state=state, candidates=candidates)
        candidate_map = {worker.name: worker for worker in candidates}

        routing_snapshot = {
            "objective": state.objective,
            "task": {
                "task_id": task.task_id,
                "title": task.title,
                "description": task.description,
                "task_type": task.task_type,
                "priority": task.priority,
                "input_context": task.input_context,
                "metadata": task.metadata,
            },
            "challenge": state.metadata.get("challenge", {}),
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "kind": asset.kind,
                    "hostname": asset.hostname,
                    "base_url": asset.base_url,
                    "services": [
                        {"port": service.port, "name": service.name, "product": service.product}
                        for service in asset.services
                    ],
                }
                for asset in state.assets.values()
            ],
            "recent_findings": [
                {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "metadata": finding.metadata,
                }
                for finding in list(state.findings.values())[-8:]
            ],
            "candidates": [
                worker.routing_profile(task, state)
                for worker in candidates
                if worker.can_route_task(task, state)[0]
            ],
            "fallback_choice": fallback_decision.model_dump(mode="json"),
        }
        if not routing_snapshot["candidates"]:
            return fallback_decision

        category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()

        try:
            decision = self.llm_client.generate_json(
                system_prompt=get_router_system_prompt(category),
                user_prompt=json.dumps(routing_snapshot, ensure_ascii=True, indent=2),
                schema=WorkerRouteDecision,
                temperature=0.1,
            )
        except Exception:
            return fallback_decision

        selected = candidate_map.get(decision.worker_name)
        if selected is None:
            return fallback_decision
        allowed, _ = selected.can_route_task(task, state)
        if not allowed:
            return fallback_decision
        return decision
