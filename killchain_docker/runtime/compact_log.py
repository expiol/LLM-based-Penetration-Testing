"""Compact run log projection for humans and LLMs."""

from __future__ import annotations
from typing import Any
from killchain_docker.llm.gateway import TokenLedger
from killchain_docker.state.run_state import RunState
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.memory.projection import RunMemoryProjection
from killchain_docker.state.projection_common import compact_text
from killchain_docker.state.report_projection import RunReportProjection


def runtime_error_payload(state: RunState) -> dict[str, Any] | None:
    return RunReportProjection(state).runtime_error_payload()


def build_compact_run_log(
    state: RunState,
    *,
    events: list[str] | None = None,
    token_ledger: TokenLedger | None = None,
) -> dict[str, Any]:
    """Return an LLM-readable run timeline without large stdout/stderr blobs."""
    challenge_projection = ChallengeProjection(state)
    memory_projection = RunMemoryProjection(state)
    report_projection = RunReportProjection(state)
    outcome = RunOutcomeStore(state)
    payload: dict[str, Any] = {
        "schema_version": 1,
        "purpose": "Compact run log for humans and LLMs. See state.json/evidence.json for full stdout, stderr, and raw tool payloads.",
        "run": {
            "run_id": state.run_id,
            **outcome.summary_payload(),
            "runtime_error": runtime_error_payload(state),
            "created_at": state.created_at.isoformat(),
            "updated_at": state.updated_at.isoformat(),
            "last_cycle_at": state.last_cycle_at.isoformat()
            if state.last_cycle_at
            else None,
        },
        "challenge": challenge_projection.payload(),
        "counts": {**report_projection.metrics()},
        "rag": report_projection.rag_payload() or {},
        "flag_candidates": report_projection.compact_flag_candidates(),
        "run_memory": memory_projection.prompt_entries(limit=30, width=260),
        "hypotheses_tail": report_projection.compact_hypotheses_tail(),
        "open_or_recent_todos": report_projection.open_or_recent_todos(),
        "timeline": report_projection.compact_rounds(),
        "orchestration_notes_tail": report_projection.compact_orchestration_notes_tail(),
        "events_tail": [
            compact_text(message, limit=300) for message in (events or [])[-80:]
        ],
        "full_artifacts": {
            "state": "state.json",
            "evidence": "evidence.json",
            "events": "events.log",
            "report": "report.md",
        },
    }
    if token_ledger is not None:
        payload["token_usage"] = token_ledger.to_dict()
    return payload


def render_compact_run_markdown(payload: dict[str, Any]) -> str:
    run = payload.get("run") or {}
    challenge = payload.get("challenge") or {}
    counts = payload.get("counts") or {}
    lines = [
        "# Compact Run Log",
        "",
        "This is the LLM-readable timeline. Full raw outputs remain in `state.json`, `evidence.json`, and `events.log`.",
        "",
        "## Run",
        "",
        f"- Run ID: `{run.get('run_id')}`",
        f"- Challenge: `{challenge.get('canonical_name') or challenge.get('name')}` ({challenge.get('category')})",
        f"- Status: `{run.get('status')}` stop_reason=`{run.get('stop_reason')}` solved=`{run.get('solved')}`",
        f"- Validated flag: `{run.get('validated_flag')}`",
        f"- Updated: `{run.get('updated_at')}`",
        f"- Counts: rounds={counts.get('rounds')} todos={counts.get('todos')} open={counts.get('open_todos')} evidence={counts.get('evidence')} flags={counts.get('flag_candidates')}",
        f"- Todo statuses: `{counts.get('todo_status_counts')}`",
        "",
    ]
    runtime_error = run.get("runtime_error")
    if isinstance(runtime_error, dict):
        lines.extend(
            [
                f"- Runtime error: `{runtime_error.get('type')}` {runtime_error.get('message')}",
                "",
            ]
        )
    rag = payload.get("rag")
    if isinstance(rag, dict) and rag:
        lines.extend(
            [
                "## RAG",
                "",
                f"- Enabled: `{rag.get('enabled')}` status=`{rag.get('status')}` policy=`{rag.get('policy')}` hints={rag.get('hint_count')}",
                "",
            ]
        )
    token_usage = payload.get("token_usage")
    if isinstance(token_usage, dict):
        lines.extend(
            [
                "## Token Usage",
                "",
                f"- Calls: {token_usage.get('llm_calls')} prompt={token_usage.get('prompt_tokens')} completion={token_usage.get('completion_tokens')} total={token_usage.get('total_tokens')}",
                "",
            ]
        )
    flags = payload.get("flag_candidates") or []
    lines.extend(["## Flag Candidates", ""])
    if flags:
        for item in flags:
            lines.append(
                f"- `{item.get('value')}` source={item.get('source')} confidence={item.get('confidence')} validated={item.get('validated')} rejected={item.get('rejected_reason')}"
            )
    else:
        lines.append("- None accepted into state.")
    lines.append("")
    memory = payload.get("run_memory") or {}
    lines.extend(["## Run Memory", ""])
    if memory:
        for key, value in memory.items():
            lines.append(f"- `{key}`: {value}")
    else:
        lines.append("- Empty.")
    lines.append("")
    lines.extend(["## Timeline", ""])
    timeline = payload.get("timeline") or []
    if timeline:
        for item in timeline:
            lines.append(f"### Cycle {item.get('cycle')}")
            lines.append("")
            lines.append(f"- Plan: {item.get('planner_summary')}")
            for assignment in item.get("assignments") or []:
                lines.append(
                    f"- Dispatch: `{assignment.get('todo_id')}` -> `{assignment.get('worker')}`"
                )
            for result in item.get("results") or []:
                lines.append(
                    f"- Result: `{result.get('todo_id')}` `{result.get('worker')}` success={result.get('success')} partial={result.get('partial')} quality={result.get('quality')} flags={result.get('flag_candidates')} :: {result.get('summary')}"
                )
                if result.get("error"):
                    lines.append(f"  Error: {result.get('error')}")
            if item.get("router_summary"):
                lines.append(f"- Router: {item.get('router_summary')}")
            if item.get("next_focus"):
                lines.append(f"- Next focus: {item.get('next_focus')}")
            lines.append("")
    else:
        lines.append("- No rounds recorded yet.")
        lines.append("")
    todos = payload.get("open_or_recent_todos") or []
    lines.extend(["## Open Or Recent Todos", ""])
    if todos:
        for todo in todos:
            lines.append(
                f"- `{todo.get('todo_id')}` status={todo.get('status')} phase={todo.get('phase')} worker={todo.get('worker')} attempts={todo.get('attempts')} family={todo.get('family')} :: {todo.get('goal')}"
            )
            if todo.get("result"):
                lines.append(f"  Result: {todo.get('result')}")
            if todo.get("error"):
                lines.append(f"  Error: {todo.get('error')}")
    else:
        lines.append("- None.")
    lines.append("")
    notes = payload.get("orchestration_notes_tail") or []
    lines.extend(["## Notes Tail", ""])
    if notes:
        lines.extend((f"- {note}" for note in notes))
    else:
        lines.append("- None.")
    lines.append("")
    lines.extend(["## Events Tail", ""])
    for message in payload.get("events_tail") or []:
        lines.append(f"- {message}")
    if not payload.get("events_tail"):
        lines.append("- None.")
    lines.append("")
    return "\n".join(lines)
