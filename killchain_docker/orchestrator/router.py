"""Worker routing strategies for task dispatch."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Sequence

from pydantic import AliasChoices, BaseModel, Field, field_validator

from killchain_docker.agents._helpers.coercion import coerce_confidence
from killchain_docker.agents.base import WorkerAgent
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.prompts import get_router_system_prompt
from killchain_docker.state import GlobalState, Task


class WorkerRouteDecision(BaseModel):
    """Structured worker-selection result.

    ``rationale`` and ``confidence`` are advisory metadata for logging; only
    ``worker_name`` drives dispatch.  Models sometimes emit ``selected_worker``;
    both keys deserialize via ``validation_alias``.  Optional fields use defaults
    so a minimal JSON object does not crash the run on missing log metadata.
    """

    worker_name: str = Field(
        validation_alias=AliasChoices("worker_name", "selected_worker"),
    )
    rationale: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    _coerce_confidence = field_validator("confidence", mode="before")(
        lambda cls, v: coerce_confidence(v)
    )


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
            "task": {
                "task_id": task.task_id,
                "title": task.title,
                "description": task.description,
                "task_type": task.task_type,
                "priority": task.priority,
                "input_context": task.input_context,
            },
            "challenge_category": str(
                state.metadata.get("challenge", {}).get("category") or "misc"
            ).lower(),
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
