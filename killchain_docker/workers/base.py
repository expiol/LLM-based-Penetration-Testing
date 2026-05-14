"""Base abstraction for orchestrator-managed workers.

This module owns the :class:`WorkerAgent` abstract base class for the
persona-worker runtime.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
from typing import Any

from killchain_docker.evidence_context import EvidenceContextBuilder
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
from killchain_docker.workers.tool_metadata import tool_metadata_contract


# ===========================================================================
# WorkerAgent — abstract base
# ===========================================================================


class WorkerAgent(ABC):
    """Abstract persona worker that can handle high-level todos."""

    name: str
    supported_todo_kinds: tuple[str, ...]
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

        context = todo.context
        excluded = {
            str(value) for value in (context.get("exclude_workers") or [])
        }
        if self.name in excluded:
            return False, "worker explicitly excluded by task metadata"

        for key in self.required_context_keys:
            value = context.get(key)
            if value in (None, "", [], {}, ()):
                return False, f"missing required context key: {key}"
        return True, None

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
        allowed_values = sorted(capability.value for capability in allowed)
        catalog = [
            {
                "capability": capability.value,
                "tool_name": spec.tool_name,
                "default_timeout_s": spec.default_timeout_s,
                "metadata_contract": tool_metadata_contract(capability),
            }
            for capability, spec in self.tool_gateway.specs.items()
            if capability in allowed
        ]
        evidence_context = EvidenceContextBuilder(max_records=10).build(state)
        decision = self.llm_client.generate_json(
            system_prompt=(
                "You are a worker deciding one concrete lower-level tool call. "
                "Choose a capability from the provided tool_catalog and provide the "
                "metadata arguments needed by that capability. Use only the "
                "field names listed in metadata_contract. "
                "The tool_catalog is the complete allowed set; never choose a "
                "capability that is not listed there. "
                "Use recent_evidence_context as grounded facts from previous tools. "
                "Do not depend on /tmp files or other scratch files written by earlier todos; "
                "read challenge files directly or regenerate needed diagnostics in the "
                "same tool call. "
                "Return only JSON matching ToolUseDecision."
            ),
            user_prompt=json.dumps(
                {
                    "worker_name": self.name,
                    "todo": task.model_dump(mode="json"),
                    "state_summary": state.summary(),
                    "recent_evidence_context": evidence_context,
                    "recent_failures": [
                        record.model_dump(mode="json")
                        for record in state.execution_log[-12:]
                        if not record.success
                    ],
                    "allowed_capabilities": allowed_values,
                    "tool_use_rules": self._tool_use_rules(allowed),
                    "tool_catalog": catalog,
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=ToolUseDecision,
            temperature=0.1,
        )
        try:
            selected = ToolCapability(decision.capability)
        except ValueError as exc:
            raise ToolExecutionError(
                f"{self.name} selected invalid tool capability {decision.capability!r}; "
                f"allowed capabilities: {', '.join(allowed_values)}"
            ) from exc
        if selected not in allowed:
            raise ToolExecutionError(
                f"{self.name} selected unavailable tool capability {selected.value!r}; "
                f"allowed capabilities: {', '.join(allowed_values)}"
            )
        return decision

    @staticmethod
    def _tool_use_rules(allowed: set[ToolCapability]) -> list[str]:
        rules = [
            "Choose exactly one capability from tool_catalog.",
            "Use recent_evidence_context before repeating diagnostics already present there.",
            "Do not read /tmp paths created by previous todos.",
        ]
        if ToolCapability.SCRIPT_EXECUTE in allowed:
            rules.extend(
                [
                    "For script.execute, make script_code self-contained and print the important stdout.",
                    "For script.execute, prefer os.environ['CTF_WRITABLE_FILES_ROOT'] for any file you intend "
                    "to mutate in place; CTF_FILES_ROOT holds the read-only originals. "
                    "Do not use shutil.copy2 on the originals (it preserves the read-only mode).",
                ]
            )
        return rules

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Execute a todo against the current shared state."""


__all__ = [
    "WorkerAgent",
]
