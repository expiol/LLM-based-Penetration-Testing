"""Solver code execution.

Wraps the :class:`ExecutionPlane` ``solver_execution`` plugin call.  Returns
a :class:`SolverExecutionOutcome` carrying the raw bundle plus the parsed
output context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidence
from nyuctf_mutil_killchain.tools import (
    ExecutionPlane,
    ToolExecutionBundle,
    ToolExecutionError,
    ToolExecutionRequest,
)


@dataclass
class SolverExecutionOutcome:
    """Result of running an LLM-generated solver inside the container."""

    success: bool
    bundle: ToolExecutionBundle | None
    error: str | None
    output_context: dict[str, Any]
    summary: str

    @property
    def stdout(self) -> str:
        return str(self.output_context.get("stdout", ""))

    @property
    def stderr(self) -> str:
        return str(self.output_context.get("stderr", ""))

    @property
    def returncode(self) -> int:
        try:
            return int(self.output_context.get("returncode", -1))
        except (TypeError, ValueError):
            return -1

    @property
    def near_miss_candidates(self) -> list[str]:
        candidates = self.output_context.get("near_miss_candidates") or []
        return [str(c) for c in candidates]


class SolverCodeExecutor:
    """Submit LLM-generated solver code to the execution plane."""

    def __init__(self, execution_plane: ExecutionPlane) -> None:
        self.execution_plane = execution_plane

    def run(
        self,
        *,
        task_id: str,
        solver_code: str,
        solver_language: str,
        evidence: SolverEvidence,
    ) -> SolverExecutionOutcome:
        request = ToolExecutionRequest(
            tool_name="solver_execution",
            parser_name="jsonl_signals",
            timeout_s=evidence.timeout_s + 10,
            metadata={
                "solver_code": solver_code,
                "files_root": evidence.files_root,
                "timeout_s": evidence.timeout_s,
                "flag_format": evidence.flag_format,
                "solver_language": solver_language,
                "challenge_files": list(evidence.challenge.get("files") or []),
            },
        )

        try:
            bundle = self.execution_plane.execute(task_id, request)
        except ToolExecutionError as exc:
            return SolverExecutionOutcome(
                success=False,
                bundle=None,
                error=str(exc),
                output_context={},
                summary="Solver execution failed.",
            )

        return SolverExecutionOutcome(
            success=True,
            bundle=bundle,
            error=None,
            output_context=dict(bundle.parsed.output_context),
            summary=bundle.parsed.summary,
        )
