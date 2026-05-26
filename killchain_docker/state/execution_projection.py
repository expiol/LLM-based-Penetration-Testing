"""Execution-history projection over durable run state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from killchain_docker.state.evidence_projection import evidence_output_context

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class ExecutionProjection:
    """Read-only execution and failure feedback for worker prompts."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def recent_failed_records(self, *, limit: int) -> list[object]:
        return [
            record for record in self.state.execution_log[-limit:] if not record.success
        ]

    def recent_script_failure_context(
        self, *, task_id: str
    ) -> dict[str, object] | None:
        same_task: list[tuple[object, dict[str, object]]] = []
        other_tasks: list[tuple[object, dict[str, object]]] = []
        for evidence in reversed(list(self.state.evidence.values())):
            if evidence.tool_name != "script_exec":
                continue
            ctx = evidence_output_context(evidence)
            if not ctx:
                continue
            failure_kind = ctx.get("failure_kind")
            returncode = ctx.get("returncode")
            has_failed = failure_kind not in (None, "", "none") or returncode not in (
                None,
                0,
                "",
            )
            if not has_failed:
                continue
            if evidence.task_id == task_id:
                same_task.append((evidence, ctx))
            else:
                other_tasks.append((evidence, ctx))
        for evidence, ctx in same_task + other_tasks[:1]:
            failure_kind = ctx.get("failure_kind")
            if failure_kind in (None, "", "none") and ctx.get("returncode") in (
                None,
                0,
                "",
            ):
                continue
            return {"evidence": evidence, "context": ctx, "failure_kind": failure_kind}
        return None
