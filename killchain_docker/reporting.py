"""Run artifact reporting helpers."""

from __future__ import annotations
from typing import Any
from killchain_docker.state.run_state import RunState
from killchain_docker.state.report_projection import RunReportProjection


def _items(payload: dict[str, object], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    return list(value) if isinstance(value, list) else []


def _strings(payload: dict[str, object], key: str) -> list[str]:
    value = payload.get(key)
    return [str(item) for item in value] if isinstance(value, list) else []


def render_markdown_report(state: RunState) -> str:
    """Render a compact markdown report from the final state."""
    payload = RunReportProjection(state).markdown_report_payload()
    overview = payload.get("overview")
    if not isinstance(overview, dict):
        overview = {}
    lines: list[str] = [
        "# AutoPentest Report",
        "",
        "## Overview",
        "",
        f"- Run ID: `{overview.get('run_id')}`",
        f"- Objective: {overview.get('objective')}",
        f"- Status: `{overview.get('status')}`",
        f"- Stop Reason: `{overview.get('stop_reason')}`",
        f"- Solved: `{overview.get('solved')}`",
        f"- Validated Flag: `{overview.get('validated_flag')}`",
        f"- Scope entries: {overview.get('scope_entries')}",
        f"- Todos: {overview.get('todos')}",
        f"- Rounds: {overview.get('rounds')}",
        f"- Assets: {overview.get('assets')}",
        f"- Findings: {overview.get('findings')}",
        f"- Artifacts: {overview.get('artifacts')}",
        f"- Routes: {overview.get('routes')}",
        f"- Flag candidates: {overview.get('flag_candidates')}",
        f"- Vulnerabilities: {overview.get('vulnerabilities')}",
        f"- Evidence items: {overview.get('evidence')}",
        "",
        "## Assets",
        "",
    ]
    runtime_error = payload.get("runtime_error")
    if runtime_error:
        lines.insert(22, str(runtime_error))
    rag = payload.get("rag")
    if rag:
        insert_at = 23 if runtime_error else 22
        lines.insert(insert_at, str(rag))
    assets = _items(payload, "assets")
    if assets:
        for asset in assets:
            lines.append(
                f"- `{asset.get('asset_id')}` `{asset.get('kind')}` {asset.get('location')}"
            )
    else:
        lines.append("- No assets recorded.")
    lines.extend(["", "## Findings", ""])
    findings = _items(payload, "findings")
    if findings:
        for finding in findings:
            lines.append(
                f"- `{finding.get('finding_id')}` [`{finding.get('severity')}`] {finding.get('title')}"
            )
            if finding.get("description"):
                lines.append(f"  {finding.get('description')}")
    else:
        lines.append("- No findings recorded.")
    lines.extend(["", "## Todos", ""])
    todos = _items(payload, "todos")
    if todos:
        for todo in todos:
            lines.append(
                f"- `{todo.get('status')}` `{todo.get('todo_id')}` {todo.get('goal')}"
            )
            if todo.get("result_summary"):
                lines.append(f"  {todo.get('result_summary')}")
            elif todo.get("error"):
                lines.append(f"  Error: {todo.get('error')}")
    else:
        lines.append("- No todos recorded.")
    lines.extend(["", "## Router Rounds", ""])
    router_rounds = _items(payload, "router_rounds")
    if router_rounds:
        for round_record in router_rounds:
            lines.append(
                f"- `cycle {round_record.get('cycle')}` {round_record.get('summary')}"
            )
    else:
        lines.append("- No router rounds recorded.")
    lines.extend(["", "## Typed Facts", ""])
    flag_candidates = _items(payload, "flag_candidates_tail")
    if flag_candidates:
        lines.append("### Flag Candidates")
        for candidate in flag_candidates:
            lines.append(
                f"- `{candidate.get('status')}` `{candidate.get('source')}` {candidate.get('value')}"
            )
    routes = _items(payload, "routes_tail")
    if routes:
        lines.append("### Routes")
        for route in routes:
            lines.append(f"- `{route.get('status_code')}` {route.get('url')}")
    if not payload.get("has_typed_facts"):
        lines.append("- No typed facts recorded.")
    lines.extend(["", "## Evidence", ""])
    evidence_items = _items(payload, "evidence")
    if evidence_items:
        for evidence in evidence_items:
            lines.append(
                f"- `{evidence.get('evidence_id')}` via `{evidence.get('tool_name')}`: {evidence.get('summary')}"
            )
    else:
        lines.append("- No evidence recorded.")
    lines.extend(["", "## Worker Notes", ""])
    worker_notes = _strings(payload, "worker_notes_tail")
    if worker_notes:
        lines.extend((f"- {note}" for note in worker_notes))
    else:
        lines.append("- No worker notes recorded.")
    lines.extend(["", "## Orchestration Notes", ""])
    orchestration_notes = _strings(payload, "orchestration_notes_tail")
    if orchestration_notes:
        lines.extend((f"- {note}" for note in orchestration_notes))
    else:
        lines.append("- No orchestration notes recorded.")
    return "\n".join(lines) + "\n"
