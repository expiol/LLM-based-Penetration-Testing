"""LLM-backed tool choice helpers for worker agents."""

from __future__ import annotations

from typing import Any

from killchain_docker.llm.gateway import LLMClient, LLMClientError
from killchain_docker.reasoning.schemas import ToolUseDecision
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability, ToolGateway
from killchain_docker.tools.core import ToolExecutionError
from killchain_docker.workers.prompts.fixed import build_fixed_tool_prompt
from killchain_docker.workers.prompts.choice import build_tool_choice_prompt


class WorkerToolChoiceMixin:
    name: str
    llm_client: LLMClient | None
    tool_gateway: ToolGateway | None

    def choose_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        allowed_capabilities: list[ToolCapability | str] | None = None,
        prior_steps: list[dict[str, Any]] | None = None,
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
        prompt = build_tool_choice_prompt(
            worker_name=self.name,
            task=task,
            state=state,
            tool_gateway=self.tool_gateway,
            allowed_capabilities=allowed_capabilities,
            prior_steps=prior_steps,
        )
        decision = self.llm_client.generate_json(
            system_prompt=prompt.system_prompt,
            user_prompt=prompt.user_prompt,
            schema=ToolUseDecision,
            temperature=0.1,
        )
        try:
            selected = ToolCapability(decision.capability)
        except ValueError as exc:
            raise ToolExecutionError(
                f"{self.name} selected invalid tool capability {decision.capability!r}; allowed capabilities: {', '.join(prompt.allowed_values)}"
            ) from exc
        if selected not in prompt.allowed:
            raise ToolExecutionError(
                f"{self.name} selected unavailable tool capability {selected.value!r}; allowed capabilities: {', '.join(prompt.allowed_values)}"
            )
        return decision

    def choose_fixed_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        capability: ToolCapability | str,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision:
        """Ask the LLM for metadata after dispatch has fixed the capability."""
        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client for tool metadata."
            )
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway for tool metadata."
            )
        prompt = build_fixed_tool_prompt(
            worker_name=self.name,
            task=task,
            state=state,
            capability=capability,
            prior_steps=prior_steps,
        )
        decision = self.llm_client.generate_json(
            system_prompt=prompt.system_prompt,
            user_prompt=prompt.user_prompt,
            schema=ToolUseDecision,
            temperature=0.1,
        )
        selected = prompt.fixed_capability
        if selected is None or ToolCapability(decision.capability) != selected:
            raise ToolExecutionError(
                f"{self.name} changed fixed capability from {selected.value!r} to {decision.capability!r}"
            )
        return decision
