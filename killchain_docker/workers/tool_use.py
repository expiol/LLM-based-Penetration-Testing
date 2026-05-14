"""Generic LLM tool-use worker."""

from __future__ import annotations

from typing import Any

from killchain_docker.state import GlobalState, PlannerSignal, Task, WorkerReport
from killchain_docker.tools import ToolExecutionError
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec


class GenericToolUseAgent(WorkerAgent):
    """High-level worker that lets the LLM select a lower-level capability."""

    name = "generic-tool-use-agent"
    supported_task_types = (
        "recon.",
        "credential.",
        "flag.hunt",
        "artifact.",
        "host.",
        "web.",
        "vuln.",
        "exploit.",
    )
    routing_summary = (
        "General worker for bounded experiments where the planner wants the "
        "worker LLM to choose a concrete tool capability and metadata."
    )

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        decision = self.choose_tool_use(task=task, state=state)
        metadata: dict[str, Any] = dict(decision.metadata)
        timeout_raw = metadata.pop("timeout_s", None)
        timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
        try:
            bundle = self.run_capability(
                task=task,
                capability=decision.capability,
                metadata=metadata,
                timeout_s=timeout_s,
            )
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"Tool-use execution failed: {exc}",
                error=str(exc),
                planner_signals=[
                    PlannerSignal(
                        summary="Tool-use execution failed; planner should choose a different task or capability.",
                        failure_reason=str(exc),
                        rationale=decision.rationale,
                    )
                ],
            )

        parsed = bundle.parsed
        output_context = dict(parsed.output_context)
        output_context["tool_use_decision"] = decision.model_dump(mode="json")
        success = bundle.result.exit_code in (None, 0)
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=success,
            summary=parsed.summary or decision.expected_signal or "Tool capability executed.",
            output_context=output_context,
            asset_updates=parsed.asset_updates,
            finding_updates=parsed.finding_updates,
            credential_updates=parsed.credential_updates,
            network_updates=parsed.network_updates,
            state_delta=bundle.state_delta,
            evidence_updates=[bundle.evidence],
            notes=list(parsed.notes),
            planner_signals=[
                PlannerSignal(
                    summary=decision.expected_signal or parsed.summary,
                    rationale=decision.rationale,
                    metadata={
                        "capability": str(decision.capability),
                        "tool_name": bundle.request.tool_name,
                    },
                )
            ],
            retryable=not success,
        )


def _build_generic(context: WorkerBuildContext) -> WorkerAgent:
    return GenericToolUseAgent(
        llm_client=context.llm_client,
        execution_plane=context.execution_plane,
    )


GROUP = "tool-use"
WORKER_CLASSES = (GenericToolUseAgent,)
WORKER_SPECS = (
    WorkerSpec(
        key="GenericToolUseAgent",
        group=GROUP,
        description=GenericToolUseAgent.routing_summary,
        factory=_build_generic,
    ),
)
