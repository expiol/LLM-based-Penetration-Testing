"""Unified Worker class with injected PersonaSpec data.

The execution loop is shared; persona differences (capabilities and routing
summary) live in the PersonaSpec catalog.
"""

from __future__ import annotations
from killchain_docker.llm.gateway import LLMClient
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, WorkerResult
from killchain_docker.tools.capabilities import (
    ToolCapability,
    supported_profiles_for_worker,
)
from killchain_docker.workers.runtime.agent import WorkerAgent
from killchain_docker.workers.personas.catalog import PersonaSpec
from killchain_docker.workers.execution.direct import run_direct_capability
from killchain_docker.workers.results.flag_validation import flag_validation_result
from killchain_docker.workers.execution.loop import run_worker_tool_loop


class Worker(WorkerAgent):
    """Unified worker driven by an injected PersonaSpec."""

    _MAX_INNER_STEPS = 3
    _MAX_METADATA_RETRIES = 1

    def __init__(
        self,
        *,
        persona: PersonaSpec,
        llm_client: LLMClient | None = None,
        execution_plane=None,
        tool_gateway=None,
        expected_flag: str | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            execution_plane=execution_plane,
            tool_gateway=tool_gateway,
        )
        self._persona = persona
        self.expected_flag = expected_flag

    @property
    def name(self) -> str:
        return self._persona.name

    @property
    def supported_todo_kinds(self) -> tuple[str, ...]:
        return self._persona.supported_todo_kinds

    @property
    def routing_summary(self) -> str:
        return self._persona.routing_summary

    @property
    def preferred_challenge_categories(self) -> tuple[str, ...]:
        return self._persona.preferred_challenge_categories

    @property
    def required_context_keys(self) -> tuple[str, ...]:
        return self._persona.required_context_keys

    @property
    def supported_dispatch_profiles(self) -> tuple[str, ...]:
        explicit = self._persona.supported_dispatch_profiles
        if explicit:
            return explicit
        return supported_profiles_for_worker(self._persona.name)

    @property
    def allowed_capabilities(self) -> tuple[ToolCapability, ...]:
        return self._persona.allowed_capabilities

    def supports(self, todo: TodoItem) -> bool:
        if self._persona.name == "flag-worker":
            return todo.phase == TodoPhase.FLAG_VALIDATION
        return True

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        if self._persona.name == "flag-worker":
            result = self._try_flag_validation(task, state)
            if result is not None:
                return result
        if self.tool_gateway is None:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} cannot run because no tool gateway is configured.",
                error="tool gateway unavailable",
                retryable=False,
            )
        directed_result = run_direct_capability(self, task, state)
        if directed_result is not None:
            return directed_result
        return run_worker_tool_loop(
            self,
            task,
            state,
            max_inner_steps=self._MAX_INNER_STEPS,
            max_metadata_retries=self._MAX_METADATA_RETRIES,
        )

    def _try_flag_validation(
        self, task: TodoItem, state: RunState
    ) -> WorkerResult | None:
        """Fast-path flag validation without tool execution."""
        return flag_validation_result(
            task, state, worker_name=self.name, expected_flag=self.expected_flag
        )


__all__ = ["Worker"]
