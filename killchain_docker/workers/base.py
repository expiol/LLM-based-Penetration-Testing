"""Base abstraction for orchestrator-managed workers.

This module owns the :class:`WorkerAgent` abstract base class and the
:class:`ReasoningOnlyWorker` marker. Helpers for flag extraction, network
context, and string normalization live in :mod:`killchain_docker.workers._helpers`.
Task constructors live in :mod:`killchain_docker.state.task_factory`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
from typing import Any, TypeVar

from pydantic import BaseModel

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.reasoning import ToolUseDecision
from killchain_docker.state import RunState, TodoItem, WorkerResult
from killchain_docker.tools import (
    ExecutionPlane,
    ToolCapability,
    ToolExecutionBundle,
    ToolExecutionError,
    ToolGateway,
)

ModelT = TypeVar("ModelT", bound=BaseModel)


# ===========================================================================
# WorkerAgent — abstract base
# ===========================================================================


class WorkerAgent(ABC):
    """Abstract worker that can handle one or more task types."""

    name: str
    supported_task_types: tuple[str, ...]
    routing_summary: str = ""
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
        tool_gateway: ToolGateway | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.execution_plane = execution_plane
        self.tool_gateway = tool_gateway or (
            ToolGateway(execution_plane) if execution_plane is not None else None
        )

    def supports(self, todo: TodoItem) -> bool:
        return True

    def can_route_task(self, todo: TodoItem, state: RunState) -> tuple[bool, str | None]:
        """Return whether the worker is eligible for a routed dispatch."""

        del state
        if not self.supports(todo):
            return False, "todo not supported"

        context = getattr(todo, "context", getattr(todo, "input_context", {}))
        metadata = getattr(todo, "metadata", {})
        excluded = {
            str(value)
            for value in (
                list(metadata.get("exclude_workers") or [])
                + list(context.get("exclude_workers") or [])
            )
        }
        if self.name in excluded:
            return False, "worker explicitly excluded by task metadata"

        for key in self.required_context_keys:
            value = context.get(key)
            if value in (None, "", [], {}, ()):
                return False, f"missing required context key: {key}"
        return True, None

    def routing_score(self, todo: TodoItem, state: RunState) -> int:
        """Minimal deterministic score exposed as context for LLM routing."""

        score = 50
        category = str(state.metadata.get("challenge", {}).get("category") or "").lower()
        if category and category in self.preferred_challenge_categories:
            score += 25
        return score

    def routing_profile(self, todo: TodoItem, state: RunState) -> dict[str, Any]:
        """Return structured metadata for LLM-assisted worker routing."""

        default_summary = (self.__doc__ or "").strip().splitlines()
        return {
            "worker_name": self.name,
            "supported_task_types": list(self.supported_task_types),
            "routing_summary": self.routing_summary or (default_summary[0] if default_summary else self.name),
            "preferred_challenge_categories": list(self.preferred_challenge_categories),
            "required_context_keys": list(self.required_context_keys),
            "heuristic_score": self.routing_score(todo, state),
        }

    def generate_structured_output(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        """Call llm_client.generate_json and return the validated result.

        Raises LLMClientError if the LLM client is not configured or the call fails.
        """

        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client but none was provided."
            )

        return self.llm_client.generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            schema=schema,
            temperature=temperature,
        )

    def run_capability(
        self,
        *,
        task: TodoItem,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle:
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway but none is configured."
            )
        return self.tool_gateway.run(
            task_id=getattr(task, "todo_id", getattr(task, "task_id", "")),
            capability=capability,
            metadata=metadata,
            timeout_s=timeout_s,
        )

    def choose_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        allowed_capabilities: list[ToolCapability | str] | None = None,
    ) -> ToolUseDecision:
        """Ask the LLM to choose one lower-level tool capability for a task."""

        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client for tool selection."
            )
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway for tool selection."
            )
        allowed = {
            ToolCapability(capability)
            for capability in (
                allowed_capabilities or list(self.tool_gateway.specs.keys())
            )
        }
        catalog = [
            {
                "capability": capability.value,
                "tool_name": spec.tool_name,
                "default_timeout_s": spec.default_timeout_s,
            }
            for capability, spec in self.tool_gateway.specs.items()
            if capability in allowed
        ]
        decision = self.llm_client.generate_json(
            system_prompt=(
                "You are a worker deciding one concrete lower-level tool call. "
                "Choose a capability from the provided catalog and provide the "
                "metadata arguments needed by that capability. Return only JSON "
                "matching ToolUseDecision."
            ),
            user_prompt=json.dumps(
                {
                    "worker_name": self.name,
                    "todo": task.model_dump(mode="json"),
                    "state_summary": state.summary(),
                    "run_memory": (
                        state.run_memory.model_dump(mode="json")
                        if hasattr(state, "run_memory")
                        else {}
                    ),
                    "recent_failures": [
                        record.model_dump(mode="json")
                        for record in state.execution_log[-12:]
                        if not record.success
                    ],
                    "tool_catalog": catalog,
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=ToolUseDecision,
            temperature=0.1,
        )
        selected = ToolCapability(decision.capability)
        if selected not in allowed:
            raise LLMClientError(
                f"LLM selected unavailable tool capability {selected.value!r}."
            )
        return decision

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Execute a todo against the current shared state."""


# ===========================================================================
# ReasoningOnlyWorker — LLM-only stage worker (no capability dispatch)
# ===========================================================================


class ReasoningOnlyWorker(WorkerAgent):
    """Worker that produces a :class:`WorkerReport` from LLM reasoning alone.

    For tasks that have no concrete tool capability to call (such as
    ``exploit.hypothesis`` or ``flag.validate``), the subclass implements a
    single ``_reason(task, state)`` method that returns a guidance object plus
    the report fields it should drive.
    """

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Subclasses still implement run; this base just documents intent."""


__all__ = [
    "ReasoningOnlyWorker",
    "WorkerAgent",
]
