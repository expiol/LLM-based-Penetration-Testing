"""Shared worker tool prompt payload assembly."""

from __future__ import annotations

from typing import Any

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.prompt_bounds import bounded_value
from killchain_docker.prompt_projection import (
    execution_record as prompt_execution_record,
    run_memory as prompt_run_memory,
    worker_artifacts as prompt_worker_artifacts,
    worker_todo as prompt_worker_todo,
)
from killchain_docker.state.common import coerce_text_items, parse_text_sequence
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.execution_projection import ExecutionProjection
from killchain_docker.state.report_projection import RunReportProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem
from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.workers.correction_constraints import execution_constraints
from killchain_docker.workers.correction_context import correction_context
from killchain_docker.workers.tool_prompt_rules import tool_use_rules


def tool_choice_payload(
    *,
    worker_name: str,
    task: TodoItem,
    state: RunState,
    allowed: set[ToolCapability],
    prior_steps: list[dict[str, Any]] | None,
    tool_catalog: list[dict[str, Any]],
) -> dict[str, Any]:
    payload = {
        "tool_catalog": tool_catalog,
        "allowed_capabilities": sorted(capability.value for capability in allowed),
        "tool_use_rules": tool_use_rules(allowed),
        **_base_payload(
            worker_name=worker_name,
            task=task,
            state=state,
            allowed=allowed,
            prior_steps=prior_steps,
            artifact_limit=10,
            evidence_limits=_evidence_limits_for_task(task),
            failure_limit=6,
        ),
        "state_summary": RunReportProjection(state).summary(),
    }
    _add_correction_context(payload, state=state, task=task, prior_steps=prior_steps)
    return payload


def fixed_tool_payload(
    *,
    worker_name: str,
    task: TodoItem,
    state: RunState,
    selected: ToolCapability,
    prior_steps: list[dict[str, Any]] | None,
    metadata_contract: dict[str, Any],
) -> dict[str, Any]:
    payload = {
        "fixed_capability": selected.value,
        "metadata_contract": metadata_contract,
        "tool_use_rules": tool_use_rules({selected}),
        **_base_payload(
            worker_name=worker_name,
            task=task,
            state=state,
            allowed={selected},
            prior_steps=prior_steps,
            artifact_limit=8,
            evidence_limits={
                "max_records": 5,
                "max_text_preview": 700,
                "max_key_lines": 10,
                "max_total_chars": 6000,
            },
            failure_limit=4,
        ),
    }
    _add_correction_context(payload, state=state, task=task, prior_steps=prior_steps)
    return payload


def _base_payload(
    *,
    worker_name: str,
    task: TodoItem,
    state: RunState,
    allowed: set[ToolCapability],
    prior_steps: list[dict[str, Any]] | None,
    artifact_limit: int,
    evidence_limits: dict[str, int],
    failure_limit: int,
) -> dict[str, Any]:
    evidence_context = EvidenceContextBuilder(**evidence_limits).build(
        state,
        allowed_capabilities=allowed,
        pinned_evidence_ids=_task_evidence_ids(task),
    )
    return {
        "worker_name": worker_name,
        "todo": prompt_worker_todo(task),
        "artifacts": prompt_worker_artifacts(state, task, limit=artifact_limit),
        "run_memory": prompt_run_memory(state),
        "recent_evidence_context": evidence_context,
        "prior_steps": bounded_value(
            prior_steps or [], width=700, list_limit=4, dict_limit=14
        ),
        "recent_failures": [
            prompt_execution_record(record)
            for record in ExecutionProjection(state).recent_failed_records(
                limit=failure_limit
            )
        ],
    }


def _add_correction_context(
    payload: dict[str, Any],
    *,
    state: RunState,
    task: TodoItem,
    prior_steps: list[dict[str, Any]] | None,
) -> None:
    repair_context = correction_context(state=state, task=task, prior_steps=prior_steps)
    if not repair_context:
        return
    constraints = execution_constraints(
        state=state,
        task=task,
        correction_context=repair_context,
        prior_steps=prior_steps or [],
    )
    if constraints:
        repair_context["execution_constraints"] = constraints
    payload["correction_context"] = repair_context


def _evidence_limits_for_task(task: TodoItem) -> dict[str, int]:
    likely_script = any(
        keyword in task.goal.lower()
        for keyword in ("script", "decrypt", "brute", "write", "compute", "solve")
    )
    return {
        "max_records": 5 if likely_script else 10,
        "max_text_preview": 900,
        "max_key_lines": 10,
        "max_total_chars": 8000,
    }


def _task_evidence_ids(task: TodoItem) -> list[str]:
    refs: list[str] = []

    def add(raw: object) -> None:
        for ref in _coerce_evidence_refs(raw):
            if ref not in refs:
                refs.append(ref)

    add(DispatchIntent.from_context(task.context).evidence_ids)
    for key in (
        "evidence_id",
        "evidence_ids",
        "prior_evidence_id",
        "prior_evidence_ids",
        "source_evidence_id",
        "source_evidence_ids",
    ):
        add(task.context.get(key))
    raw_intent = task.context.get("dispatch_intent")
    if isinstance(raw_intent, dict):
        for key in (
            "evidence_id",
            "evidence_ids",
            "prior_evidence_id",
            "prior_evidence_ids",
            "source_evidence_id",
            "source_evidence_ids",
        ):
            add(raw_intent.get(key))
    return refs


def _coerce_evidence_refs(raw: object) -> list[str]:
    if raw in (None, "", {}, [], ()):
        return []
    if isinstance(raw, (list, tuple, set)):
        return coerce_text_items(raw)
    text = str(raw).strip()
    parsed = parse_text_sequence(text)
    if parsed is not None:
        return coerce_text_items(parsed)
    return [text] if text else []
