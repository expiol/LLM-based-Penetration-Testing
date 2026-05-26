"""Step-history records for worker tool loops."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability
from killchain_docker.tools.core import ToolExecutionBundle
from killchain_docker.workers.execution_failures import metadata_preview


def validation_error_step(
    step: int,
    capability: ToolCapability | None,
    rationale: str,
    error_text: str,
    failure_kind: str,
    selected_metadata: dict[str, object] | None = None,
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


def executed_step(
    step: int,
    capability: ToolCapability,
    rationale: str,
    bundle: ToolExecutionBundle,
    output_context: dict[str, object],
) -> dict[str, object]:
    return {
        "step": step,
        "capability": capability.value,
        "rationale": rationale,
        "summary": bundle.tool_output.summary,
        "flag_candidates": output_context.get("flag_candidates", []),
        "near_miss_candidates": output_context.get("near_miss_candidates", []),
        "traceback": str(output_context.get("traceback", "")),
        "stdout_preview": str(output_context.get("stdout", ""))[:2000],
        "stderr_preview": str(output_context.get("stderr", ""))[:1500],
        "returncode": output_context.get("returncode"),
        "failure_kind": output_context.get("failure_kind"),
        "failure_detail": output_context.get("failure_detail"),
        "executed": True,
    }
