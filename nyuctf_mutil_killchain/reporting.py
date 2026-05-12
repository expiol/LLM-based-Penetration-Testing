"""Run artifact reporting helpers."""

from __future__ import annotations

from nyuctf_mutil_killchain.state import GlobalState


def render_markdown_report(state: GlobalState) -> str:
    """Render a compact markdown report from the final state."""

    lines: list[str] = [
        "# AutoPentest Report",
        "",
        "## Overview",
        "",
        f"- Run ID: `{state.run_id}`",
        f"- Objective: {state.objective}",
        f"- Status: `{state.status}`",
        f"- Solved: `{state.solved}`",
        f"- Validated Flag: `{state.validated_flag or 'n/a'}`",
        f"- Scope entries: {len(state.authorized_scope)}",
        f"- Assets: {len(state.assets)}",
        f"- Findings: {len(state.findings)}",
        f"- Evidence items: {len(state.evidence)}",
        "",
        "## Assets",
        "",
    ]

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

    lines.extend(["", "## Evidence", ""])
    if state.evidence:
        for evidence in sorted(state.evidence.values(), key=lambda item: item.evidence_id):
            lines.append(f"- `{evidence.evidence_id}` via `{evidence.tool_name}`: {evidence.summary}")
    else:
        lines.append("- No evidence recorded.")

    lines.extend(["", "## Worker Notes", ""])
    if state.notes:
        for note in state.notes:
            lines.append(f"- {note}")
    else:
        lines.append("- No worker notes recorded.")

    lines.extend(["", "## Orchestration Notes", ""])
    if state.orchestration_notes:
        for note in state.orchestration_notes:
            lines.append(f"- {note}")
    else:
        lines.append("- No orchestration notes recorded.")

    return "\n".join(lines) + "\n"
