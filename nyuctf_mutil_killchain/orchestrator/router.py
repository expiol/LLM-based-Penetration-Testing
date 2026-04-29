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


class LLMWorkerRouter(WorkerRouter):
    """LLM-assisted worker router with fail-fast behavior."""

    def __init__(self, llm_client: LLMClient) -> None:
        if llm_client is None:
            raise LLMClientError("LLMWorkerRouter requires an LLM client.")
        self.llm_client = llm_client

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
        }
        if not routing_snapshot["candidates"]:
            raise LLMClientError(
                f"No routable worker candidates remained for task {task.task_id} ({task.task_type})."
            )

        category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()

        decision = self.llm_client.generate_json(
            system_prompt=get_router_system_prompt(category),
            user_prompt=json.dumps(routing_snapshot, ensure_ascii=True, indent=2),
            schema=WorkerRouteDecision,
            temperature=0.1,
        )

        selected = candidate_map.get(decision.worker_name)
        if selected is None:
            raise LLMClientError(
                f"LLM router selected unknown worker {decision.worker_name!r} "
                f"for task {task.task_id}; candidates were {sorted(candidate_map)}."
            )
        allowed, _ = selected.can_route_task(task, state)
        if not allowed:
            raise LLMClientError(
                f"LLM router selected non-routable worker {decision.worker_name!r} "
                f"for task {task.task_id}."
            )
        return decision
