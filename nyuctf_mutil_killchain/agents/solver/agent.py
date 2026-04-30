"""SolverAgent: thin pipeline orchestrator.

Composes :class:`SolverEvidenceComposer`, :class:`SolverPromptBuilder`,
:class:`SolverCodeExecutor`, :class:`SolverResultParser`, and
:class:`SolverRetryPolicy`.  The agent itself owns no business logic.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.evidence import (
    SolverEvidence,
    SolverEvidenceComposer,
)
from nyuctf_mutil_killchain.agents.solver.executor import SolverCodeExecutor
from nyuctf_mutil_killchain.agents.solver.parser import SolverResultParser
from nyuctf_mutil_killchain.agents.solver.prompts import SolverPromptBuilder
from nyuctf_mutil_killchain.agents.solver.retry import SolverRetryPolicy
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import build_flag_validation_task
from nyuctf_mutil_killchain.tools import ExecutionPlane


_CATEGORY_TIMEOUT: dict[str, int] = {
    "crypto": 180,
    "rev": 120,
    "pwn": 120,
    "forensics": 120,
    "web": 60,
    "misc": 120,
}


class SolverAgent(WorkerAgent):
    """LLM-driven solver: write a script, execute it, capture flag candidates."""

    name = "solver-agent"
    supported_task_types = ("solve.generate_script",)
    routing_summary = (
        "LLM-driven solver that writes and executes custom scripts to solve the challenge. "
        "The most powerful agent - combines all evidence into an executable solution."
    )
    preferred_challenge_categories = ("crypto", "rev", "web", "forensics", "pwn", "misc")

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
        composer: SolverEvidenceComposer | None = None,
        prompt_builder: SolverPromptBuilder | None = None,
        executor: SolverCodeExecutor | None = None,
        parser: SolverResultParser | None = None,
        retry_policy: SolverRetryPolicy | None = None,
    ) -> None:
        super().__init__(llm_client=llm_client, execution_plane=execution_plane)
        self.composer = composer or SolverEvidenceComposer()
        self.prompt_builder = prompt_builder or SolverPromptBuilder()
        self._executor = executor
        self.parser = parser or SolverResultParser()
        self.retry_policy = retry_policy or SolverRetryPolicy()

    def _resolve_executor(self) -> SolverCodeExecutor | None:
        if self._executor is not None:
            return self._executor
        if self.execution_plane is None:
            return None
        return SolverCodeExecutor(self.execution_plane)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.llm_client is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an LLM client; none is configured.",
                error="SolverAgent.llm_client is None",
                retryable=False,
            )

        executor = self._resolve_executor()
        if executor is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver agent requires an execution plane; none is configured.",
                error="SolverAgent.execution_plane is None",
                retryable=False,
            )

        evidence = self.composer.compose(task, state)
        evidence.timeout_s = self._resolve_timeout(task, evidence.category)

        sys_p, usr_p = self.prompt_builder.build(evidence)
        guidance = self.generate_structured_output(
            system_prompt=sys_p,
            user_prompt=usr_p,
            schema=SolverCodeGuidance,
            temperature=0.3,
        )
        if not guidance.solver_code.strip():
            raise LLMClientError(
                "LLM failed to generate non-empty solver_code for solve.generate_script."
            )

        outcome = executor.run(
            task_id=task.task_id,
            solver_code=guidance.solver_code,
            solver_language=guidance.solver_language,
            evidence=evidence,
        )
        if not outcome.success:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Solver execution failed.",
                error=outcome.error,
                retryable=False,
                notes=[
                    f"LLM generated {guidance.solver_language} solver "
                    f"(confidence: {guidance.confidence:.1%}).",
                ],
            )

        flags = self.parser.extract(outcome, guidance)
        retry_plan = self.retry_policy.decide(
            task=task,
            evidence=evidence,
            outcome=outcome,
            flags=flags,
            guidance=guidance,
        )

        new_tasks = [
            build_flag_validation_task(candidate, source="solver_execution")
            for candidate in flags.flag_candidates
        ]
        for cleaned in flags.cleaned_near_miss[:3]:
            new_tasks.append(
                build_flag_validation_task(cleaned, source="solver_near_miss_cleaned")
            )
        if retry_plan.retry_task is not None:
            new_tasks.append(retry_plan.retry_task)

        output_context = dict(outcome.output_context)
        output_context["flag_candidates"] = flags.flag_candidates
        output_context["solver_code_preview"] = guidance.solver_code[:2000]
        output_context["solver_reasoning"] = guidance.reasoning
        output_context["solver_confidence"] = guidance.confidence
        if guidance.reasoning:
            output_context["llm_summary"] = guidance.summary

        worker_notes: list[str] = [
            f"LLM generated {guidance.solver_language} solver "
            f"(confidence: {guidance.confidence:.1%}).",
        ]
        if guidance.reasoning:
            worker_notes.append(f"Reasoning: {guidance.reasoning[:300]}")
        worker_notes.extend(retry_plan.notes)
        if flags.cleaned_near_miss:
            worker_notes.append(
                f"Auto-cleaned {len(flags.cleaned_near_miss)} near-miss candidate(s) "
                f"for validation: {flags.cleaned_near_miss[:3]}"
            )

        bundle = outcome.bundle
        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=flags.has_real_flag,
            summary=outcome.summary,
            output_context=output_context,
            asset_updates=list(bundle.parsed.asset_updates) if bundle else [],
            finding_updates=list(bundle.parsed.finding_updates) if bundle else [],
            credential_updates=list(bundle.parsed.credential_updates) if bundle else [],
            evidence_updates=[bundle.evidence] if bundle else [],
            new_tasks=new_tasks,
            notes=worker_notes + (list(bundle.parsed.notes) if bundle else []) + [
                f"{self.name} executed LLM-generated solver "
                f"(attempt {evidence.attempt_number})."
            ],
            retryable=False if retry_plan.should_retry else not flags.has_real_flag,
        )

    @staticmethod
    def _resolve_timeout(task: Task, category: str) -> int:
        default_timeout = _CATEGORY_TIMEOUT.get(category, 60)
        return int(task.input_context.get("solver_timeout_s", default_timeout))
