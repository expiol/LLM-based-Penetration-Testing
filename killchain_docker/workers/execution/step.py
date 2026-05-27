"""Single-step worker tool selection, metadata prep, and execution."""

from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urlparse

from killchain_docker.llm.gateway import LLMClientError, LLMFailureKind
from killchain_docker.reasoning.schemas import ToolUseDecision
from killchain_docker.memory.durable import DurableMemoryUpdate
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.domain import Hypothesis
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle, ToolExecutionError
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.workers.execution.failures import (
    metadata_failure_result,
    metadata_preview,
)
from killchain_docker.workers.tooling.metadata.router import normalize_tool_metadata


ToolSelection = tuple[
    ToolCapability,
    dict[str, object],
    str,
    str | None,
    dict[str, str],
    list[DurableMemoryUpdate],
]


class LoopExecutionAgent(Protocol):
    name: str
    allowed_capabilities: tuple[ToolCapability, ...]

    def report_progress(
        self, state: RunState, task: TodoItem, message: str
    ) -> None: ...

    def report_flag_candidates(
        self, state: RunState, task: TodoItem, candidates
    ) -> None: ...

    def run_capability(
        self,
        *,
        task: TodoItem,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle: ...

    def choose_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        allowed_capabilities: list[ToolCapability | str] | None = None,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision: ...

    def choose_fixed_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        capability: ToolCapability | str,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision: ...


def run_tool_step(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    prior_steps: list[dict[str, object]],
    max_metadata_retries: int,
    accumulated_hypotheses: list[Hypothesis],
    accumulated_memory: dict[str, str],
    accumulated_durable_memory: list[DurableMemoryUpdate],
) -> tuple[ToolCapability, str, ToolExecutionBundle] | WorkerResult:
    metadata_retries = 0
    capability = None
    forced_capability: ToolCapability | None = None
    shell_python_script_rescue_used = False
    rationale = ""
    selected_metadata: dict[str, object] | None = None
    while True:
        try:
            if forced_capability is not None:
                capability = forced_capability
            (
                capability,
                selected_metadata,
                rationale,
                hypothesis_text,
                mem_updates,
                durable_updates,
            ) = _select_step_tool(
                agent,
                task,
                state,
                step=step,
                prior_steps=prior_steps,
                forced_capability=forced_capability,
            )
            forced_capability = None
            if hypothesis_text:
                accumulated_hypotheses.append(Hypothesis(title=hypothesis_text))
            if mem_updates:
                accumulated_memory.update(mem_updates)
            if durable_updates:
                accumulated_durable_memory.extend(durable_updates)
            bundle = _execute_step(
                agent,
                task,
                state,
                step=step,
                capability=capability,
                selected_metadata=selected_metadata,
            )
            return (capability, rationale, bundle)
        except LLMClientError as exc:
            if exc.kind is not LLMFailureKind.SCHEMA_VALIDATION:
                raise
            error_text = str(exc)
            failure_kind = "schema_validation"
            metadata_retries += 1
            prior_steps.append(
                _validation_error_step(
                    step,
                    capability,
                    rationale,
                    error_text,
                    failure_kind,
                    selected_metadata,
                )
            )
            if metadata_retries > max_metadata_retries:
                return metadata_failure_result(
                    task,
                    agent.name,
                    capability,
                    error_text,
                    failure_kind,
                    selected_metadata,
                    prior_steps,
                )
        except (ToolExecutionError, ValueError) as exc:
            error_text = str(exc)
            failure_kind = ToolGuardPolicy.metadata_failure_kind(error_text, capability)
            metadata_retries += 1
            prior_steps.append(
                _validation_error_step(
                    step,
                    capability,
                    rationale,
                    error_text,
                    failure_kind,
                    selected_metadata,
                )
            )
            if (
                metadata_retries > max_metadata_retries
                and failure_kind == "shell_python_complexity"
                and capability == ToolCapability.SHELL_EXEC
                and ToolCapability.SCRIPT_EXEC in agent.allowed_capabilities
                and not shell_python_script_rescue_used
            ):
                shell_python_script_rescue_used = True
                forced_capability = ToolCapability.SCRIPT_EXEC
                continue
            if metadata_retries > max_metadata_retries:
                return metadata_failure_result(
                    task,
                    agent.name,
                    capability,
                    error_text,
                    failure_kind,
                    selected_metadata,
                    prior_steps,
                )


def prepare_execution_metadata(
    *,
    capability: ToolCapability,
    todo: TodoItem,
    state: RunState,
    selected_metadata: dict[str, object],
    worker_name: str,
) -> dict[str, object]:
    metadata = normalize_tool_metadata(capability, todo, state, selected_metadata)
    if worker_name == "recon-worker":
        return _recon_metadata_defaults(metadata, state)
    return metadata


def fixed_llm_capability(
    todo: TodoItem, allowed_capabilities: tuple[ToolCapability, ...]
) -> ToolCapability | None:
    """Return capabilities that should hard-bind LLM metadata generation.

    ``shell.exec`` remains a routing and batching hint. It is intentionally not
    fixed here because shell and script are both universal execution-closure
    tools, and many file/binary parsing goals are safer as bounded scripts.
    """
    intent = DispatchIntent.from_context(todo.context)
    raw = str(intent.required_capability or "").strip()
    if not raw:
        return None
    try:
        capability = ToolCapability(raw)
    except ValueError:
        return None
    if capability != ToolCapability.SCRIPT_EXEC:
        return None
    if capability not in allowed_capabilities:
        return None
    return capability


def choose_capability(
    agent: LoopExecutionAgent,
    todo: TodoItem,
    state: RunState,
    *,
    allowed_capabilities: tuple[ToolCapability, ...],
    prior_steps: list[dict[str, object]] | None = None,
) -> ToolSelection:
    decision = agent.choose_tool_use(
        task=todo,
        state=state,
        allowed_capabilities=list(allowed_capabilities),
        prior_steps=prior_steps,
    )
    return (
        ToolCapability(decision.capability),
        dict(decision.metadata),
        decision.rationale,
        decision.hypothesis,
        dict(decision.memory_updates) if decision.memory_updates else {},
        list(decision.durable_memory_updates) if decision.durable_memory_updates else [],
    )


def _select_step_tool(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    prior_steps: list[dict[str, object]],
    forced_capability: ToolCapability | None = None,
) -> ToolSelection:
    fixed_capability = forced_capability or fixed_llm_capability(
        task, agent.allowed_capabilities
    )
    if fixed_capability is not None:
        agent.report_progress(
            state,
            task,
            f"{agent.name} preparing {fixed_capability.value} for step {step + 1}",
        )
        decision = agent.choose_fixed_tool_use(
            task=task,
            state=state,
            capability=fixed_capability,
            prior_steps=prior_steps if prior_steps else None,
        )
        selected = (
            fixed_capability,
            dict(decision.metadata),
            decision.rationale,
            decision.hypothesis,
            dict(decision.memory_updates) if decision.memory_updates else {},
            list(decision.durable_memory_updates) if decision.durable_memory_updates else [],
        )
    else:
        agent.report_progress(
            state, task, f"{agent.name} choosing tool for step {step + 1}"
        )
        selected = choose_capability(
            agent,
            task,
            state,
            allowed_capabilities=agent.allowed_capabilities,
            prior_steps=prior_steps if prior_steps else None,
        )
    capability = selected[0]
    agent.report_progress(
        state, task, f"{agent.name} selected {capability.value} for step {step + 1}"
    )
    return selected


def _execute_step(
    agent: LoopExecutionAgent,
    task: TodoItem,
    state: RunState,
    *,
    step: int,
    capability: ToolCapability,
    selected_metadata: dict[str, object],
) -> ToolExecutionBundle:
    metadata = prepare_execution_metadata(
        capability=capability,
        todo=task,
        state=state,
        selected_metadata=selected_metadata,
        worker_name=agent.name,
    )
    timeout_raw = metadata.pop("timeout_s", None)
    timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
    agent.report_progress(
        state, task, f"{agent.name} executing {capability.value} for step {step + 1}"
    )
    bundle = agent.run_capability(
        task=task, capability=capability, metadata=metadata, timeout_s=timeout_s
    )
    agent.report_progress(
        state, task, f"{agent.name} completed {capability.value} for step {step + 1}"
    )
    if bundle.state_delta.flag_candidates:
        agent.report_flag_candidates(state, task, bundle.state_delta.flag_candidates)
    return bundle


def _validation_error_step(
    step: int,
    capability: ToolCapability | None,
    rationale: str,
    error_text: str,
    failure_kind: str,
    selected_metadata: dict[str, object] | None,
) -> dict[str, object]:
    cap_str = (
        capability.value
        if capability and hasattr(capability, "value")
        else str(capability or "unknown")
    )
    record: dict[str, object] = {
        "step": step,
        "capability": cap_str,
        "rationale": rationale,
        "summary": f"VALIDATION ERROR: {error_text}",
        "flag_candidates": [],
        "stdout_preview": "",
        "stderr_preview": error_text,
        "returncode": -1,
        "failure_kind": failure_kind,
        "failure_detail": error_text,
        "executed": False,
    }
    if selected_metadata:
        record["selected_metadata"] = metadata_preview(selected_metadata)
    return record


def _recon_metadata_defaults(
    metadata: dict[str, object], state: RunState
) -> dict[str, object]:
    scope = str(
        metadata.get("scope")
        or (state.authorized_scope[0] if state.authorized_scope else "")
    )
    parsed = urlparse(scope)
    if parsed.scheme in {"http", "https"}:
        metadata.setdefault("base_url", scope)
        metadata.setdefault("hostname", parsed.hostname or "")
    else:
        metadata.setdefault("hostname", parsed.hostname or scope)
    metadata.setdefault("asset_id", str(metadata.get("asset_id") or "seed-asset"))
    return metadata


__all__ = [
    "LoopExecutionAgent",
    "ToolSelection",
    "choose_capability",
    "fixed_llm_capability",
    "prepare_execution_metadata",
    "run_tool_step",
]
