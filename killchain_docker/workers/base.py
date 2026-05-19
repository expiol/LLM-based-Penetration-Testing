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
from killchain_docker.prompt_bounds import bounded_value, trim_text
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
        # Trim evidence when script generation is likely to preserve output budget
        likely_script = any(
            kw in task.goal.lower()
            for kw in ("script", "decrypt", "brute", "write", "compute", "solve")
        )
        max_evidence = 5 if likely_script else 10
        evidence_context = EvidenceContextBuilder(max_records=max_evidence).build(
            state, allowed_capabilities=allowed
        )

        # Bounded correction context from the last failed script step.
        correction_context = None
        if prior_steps:
            last = prior_steps[-1]
            if (
                last.get("capability") == "script.exec"
                and (last.get("returncode") not in (None, 0) or not last.get("flag_candidates"))
            ):
                correction_context = {
                    "instruction": (
                        "The previous script attempt failed or produced no flag. "
                        "Analyze the error below and write a CORRECTED script. "
                        "Do NOT repeat the same approach without fixing the issue."
                    ),
                    "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
                    "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
                    "failure_kind": last.get("failure_kind"),
                    "failure_detail": last.get("failure_detail"),
                }

        user_payload = {
            # ACTION-CRITICAL: tool catalog first for attention proximity
            "tool_catalog": catalog,
            "allowed_capabilities": allowed_values,
            "tool_use_rules": self._tool_use_rules(allowed),
            # TASK CONTEXT
            "worker_name": self.name,
            "todo": self._serialize_task_for_prompt(task),
            "working_memory": self._serialize_working_memory(state),
            # EVIDENCE
            "recent_evidence_context": evidence_context,
            "prior_steps": bounded_value(prior_steps or [], width=700, list_limit=4, dict_limit=14),
            # BACKGROUND (least critical)
            "state_summary": state.summary(),
            "recent_failures": [
                self._serialize_execution_record(record)
                for record in state.execution_log[-6:]
                if not record.success
            ],
        }
        if correction_context:
            user_payload["correction_context"] = correction_context

        allowed_str = ", ".join(f"'{v}'" for v in allowed_values)
        script_reminder = (
            "CRITICAL: For script.exec, 'script_code' is MANDATORY and must contain "
            "the COMPLETE executable source code as a string — not a description of what "
            "to write, but the actual runnable Python/bash code. "
        ) if ToolCapability.SCRIPT_EXEC in allowed else ""
        shell_reminder = (
            "For shell.exec, 'command' is MANDATORY and must contain the full shell "
            "command to execute via bash -c. You can use any tool installed in the "
            "container: curl, nmap, sqlmap, strings, file, binwalk, r2, tshark, etc. "
        ) if ToolCapability.SHELL_EXEC in allowed else ""
        decision = self.llm_client.generate_json(
            system_prompt=(
                f"You are {self.name}. Your ONLY available capabilities are: [{allowed_str}]. "
                "You MUST choose exactly one capability from this list. Any other capability "
                "will be REJECTED — do not select capabilities you saw in evidence from other workers. "
                "Provide the metadata arguments needed by that capability using only the "
                "field names listed in its metadata_contract. "
                f"{shell_reminder}"
                f"{script_reminder}"
                "Use recent_evidence_context as grounded facts from previous tools. "
                "If prior_steps is non-empty, use those results to inform your choice — "
                "do not repeat a tool that already produced its evidence. "
                "If correction_context is present, you MUST fix the identified error "
                "in your next script — do not repeat the same broken approach. "
                "Do not depend on /tmp files or other scratch files written by earlier todos; "
                "read challenge files directly or regenerate needed diagnostics in the "
                "same tool call. "
                "Use working_memory as established facts from prior analysis. "
                "You may set memory_updates to store key discoveries (algorithm names, "
                "keys, constants) for future reference. "
                "Return only JSON matching ToolUseDecision."
            ),
            user_prompt=json.dumps(
                user_payload,
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
    def _serialize_task_for_prompt(task: TodoItem) -> dict[str, Any]:
        return {
            "todo_id": task.todo_id,
            "goal": trim_text(task.goal, width=420),
            "phase": task.phase,
            "context": bounded_value(task.context, width=420, list_limit=8, dict_limit=14),
            "priority": task.priority,
            "success_criteria": bounded_value(task.success_criteria, width=260, list_limit=6),
            "constraints": bounded_value(task.constraints, width=260, list_limit=6),
            "status": task.status,
            "assigned_worker": task.assigned_worker,
            "result_summary": trim_text(task.result_summary, width=320),
            "dedupe_key": task.dedupe_key,
            "attempts": task.attempts,
            "max_attempts": task.max_attempts,
            "error": trim_text(task.error, width=220),
        }

    @staticmethod
    def _serialize_working_memory(state: RunState) -> dict[str, str]:
        return {
            str(key): trim_text(value, width=360)
            for key, value in list(state.working_memory.items())[-20:]
        }

    @staticmethod
    def _serialize_execution_record(record) -> dict[str, Any]:
        return {
            "task_id": record.task_id,
            "worker_name": record.worker_name,
            "success": record.success,
            "summary": trim_text(record.summary, width=320),
            "error": trim_text(record.error, width=220),
        }

    @staticmethod
    def _tool_use_rules(allowed: set[ToolCapability]) -> list[str]:
        rules = [
            "Choose exactly one capability from tool_catalog.",
            "Use recent_evidence_context before repeating diagnostics already present there.",
        ]
        if ToolCapability.SHELL_EXEC in allowed:
            rules.extend(
                [
                    "For shell.exec, put the full command string in 'command'. "
                    "You can use pipes, redirects, compound commands, and any tool "
                    "installed in the container (curl, nmap, sqlmap, strings, file, "
                    "binwalk, r2, objdump, tshark, sqlite3, python3, etc.).",
                    "Prefer shell.exec for quick one-liners: file inspection, HTTP requests, "
                    "port scanning, grepping for flags, running installed tools.",
                ]
            )
        if ToolCapability.SCRIPT_EXEC in allowed:
            rules.extend(
                [
                    "For script.exec, make script_code self-contained and print results to stdout.",
                    "Prefer script.exec for multi-step logic: crypto solvers, binary exploits, "
                    "brute-force loops, complex data transformations.",
                    "Challenge files are at /home/ctfplayer/ctf_files by default.",
                ]
            )
        return rules

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Execute a todo against the current shared state."""


__all__ = [
    "WorkerAgent",
]
