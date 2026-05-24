"""Run artifact reporting helpers."""

from __future__ import annotations

from killchain_docker.knowledge import public_rag_payload
from killchain_docker.state import RunState


def _compact_text(value: object, *, limit: int = 360) -> str:
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 15)].rstrip() + "...[truncated]"


def _runtime_error_line(state: RunState) -> str | None:
    payload = state.metadata.get("runtime_error")
    if not isinstance(payload, dict):
        return None
    error_type = _compact_text(payload.get("type") or "RuntimeError", limit=80)
    message = _compact_text(payload.get("message"), limit=360)
    return f"- Runtime Error: `{error_type}` {message}".rstrip()


def _rag_line(state: RunState) -> str | None:
    payload = public_rag_payload(state.metadata.get("rag"))
    if not payload:
        return None
    return (
        "- RAG: "
        f"enabled=`{payload.get('enabled')}` "
        f"status=`{payload.get('status')}` "
        f"policy=`{payload.get('policy')}` "
        f"hints={payload.get('hint_count')}"
    )


def render_markdown_report(state: RunState) -> str:
    """Render a compact markdown report from the final state."""

    lines: list[str] = [
        "# AutoPentest Report",
        "",
        "## Overview",
        "",
        f"- Run ID: `{state.run_id}`",
        f"- Objective: {state.objective}",
        f"- Status: `{state.status}`",
        f"- Stop Reason: `{state.stop_reason or 'n/a'}`",
        f"- Solved: `{state.solved}`",
        f"- Validated Flag: `{state.validated_flag or 'n/a'}`",
        f"- Scope entries: {len(state.authorized_scope)}",
        f"- Todos: {len(state.todos)}",
        f"- Rounds: {len(state.rounds)}",
        f"- Assets: {len(state.assets)}",
        f"- Findings: {len(state.findings)}",
        f"- Artifacts: {len(state.artifacts)}",
        f"- Routes: {len(state.routes)}",
        f"- Flag candidates: {len(state.flag_candidates)}",
        f"- Vulnerabilities: {len(state.vulnerabilities)}",
        f"- Evidence items: {len(state.evidence)}",
        "",
        "## Assets",
        "",
    ]
    runtime_error = _runtime_error_line(state)
    if runtime_error:
        lines.insert(22, runtime_error)
    rag = _rag_line(state)
    if rag:
        insert_at = 23 if runtime_error else 22
        lines.insert(insert_at, rag)

    if state.assets:
        for asset in sorted(state.assets.values(), key=lambda item: item.asset_id):
            location = asset.base_url or asset.hostname or asset.ip_address or "n/a"
            lines.append(f"- `{asset.asset_id}` `{asset.kind}` {location}")
    else:
        lines.append("- No assets recorded.")

    lines.extend(["", "## Findings", ""])
    if state.findings:
        for finding in sorted(state.findings.values(), key=lambda item: item.finding_id):
            lines.append(f"- `{finding.finding_id}` [`{finding.severity}`] {finding.title}")
            if finding.description:
                lines.append(f"  {finding.description}")
    else:
        lines.append("- No findings recorded.")

    lines.extend(["", "## Todos", ""])
    if state.todos:
        for todo in state.todos:
            lines.append(f"- `{todo.status}` `{todo.todo_id}` {todo.goal}")
            if todo.result_summary:
                lines.append(f"  {todo.result_summary}")
            elif todo.error:
                lines.append(f"  Error: {todo.error}")
    else:
        lines.append("- No todos recorded.")

    lines.extend(["", "## Router Rounds", ""])
    if state.rounds:
        for round_record in state.rounds:
            lines.append(
                f"- `cycle {round_record.cycle}` {round_record.summary.summary}"
            )
    else:
        lines.append("- No router rounds recorded.")

    lines.extend(["", "## Typed Facts", ""])
    if state.flag_candidates:
        lines.append("### Flag Candidates")
        for candidate in list(state.flag_candidates.values())[-20:]:
            status = "unknown" if candidate.validated is None else str(candidate.validated)
            lines.append(
                f"- `{status}` `{candidate.source or 'unknown'}` {candidate.value}"
            )
    if state.routes:
        lines.append("### Routes")
        for route in list(state.routes.values())[-20:]:
            code = route.status_code if route.status_code is not None else "n/a"
            lines.append(f"- `{code}` {route.url}")
    if not (state.flag_candidates or state.routes or state.vulnerabilities):
        lines.append("- No typed facts recorded.")

    lines.extend(["", "## Evidence", ""])
    if state.evidence:
        for evidence in sorted(state.evidence.values(), key=lambda item: item.evidence_id):
            lines.append(f"- `{evidence.evidence_id}` via `{evidence.tool_name}`: {evidence.summary}")
    else:
        lines.append("- No evidence recorded.")

    lines.extend(["", "## Worker Notes", ""])
    if state.notes:
        for note in state.notes[-50:]:
            lines.append(f"- {note}")
    else:
        lines.append("- No worker notes recorded.")

    lines.extend(["", "## Orchestration Notes", ""])
    if state.orchestration_notes:
        for note in state.orchestration_notes[-50:]:
            lines.append(f"- {note}")
    else:
        lines.append("- No orchestration notes recorded.")

    return "\n".join(lines) + "\n"
