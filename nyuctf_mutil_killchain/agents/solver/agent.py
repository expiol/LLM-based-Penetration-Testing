"""SolverAgent: thin pipeline orchestrator.

Composes :class:`SolverEvidenceComposer`, :class:`SolverPromptBuilder`,
:class:`SolverCodeExecutor`, :class:`SolverResultParser`, and
:class:`SolverRetryPolicy`.  The agent itself owns no business logic.
"""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import WorkerAgent
from nyuctf_mutil_killchain.agents.reasoning import SolverCodeGuidance
from nyuctf_mutil_killchain.agents.solver.evidence import (
    SolverEvidence,
    SolverEvidenceComposer,
)
from nyuctf_mutil_killchain.agents.solver.executor import SolverCodeExecutor
from nyuctf_mutil_killchain.agents.solver.lint import (
    SolverLintResult,
    lint_solver_code,
)
from nyuctf_mutil_killchain.agents.solver.parser import SolverResultParser
from nyuctf_mutil_killchain.agents.solver.prompts import SolverPromptBuilder
from nyuctf_mutil_killchain.agents.solver.retry import SolverRetryPolicy
from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.state.task_factory import build_flag_validation_tasks
from nyuctf_mutil_killchain.tools import ExecutionPlane


_CATEGORY_TIMEOUT: dict[str, int] = {
    "crypto": 180,
    "rev": 120,
    "pwn": 120,
    "forensics": 120,
    "web": 60,
    "misc": 120,
}

# How many extra LLM round-trips we'll spend regenerating solver code that
# fails the cheap in-process lint (SyntaxError or missing-stdlib-import).
# Two extra attempts is enough to absorb DeepSeek's typical "stray colon"
# / "forgot ``import sys``" noise without spending the full retry budget.
_LINT_RETRY_BUDGET = 2


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

        guidance, lint_attempts = self._generate_lint_clean_solver_code(evidence)
        worker_lint_notes: list[str] = []
        if lint_attempts > 0:
            worker_lint_notes.append(
                f"Lint pre-check rejected {lint_attempts} initial draft(s) "
                f"and re-prompted the LLM in-process before container dispatch."
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

        flag_format = (evidence.flag_format or "").strip()
        ff_prefix = None
        if flag_format and "{" in flag_format:
            ff_prefix = flag_format.split("{", 1)[0].strip() or None
        flags = self.parser.extract(outcome, guidance, flag_format_prefix=ff_prefix)
        retry_plan = self.retry_policy.decide(
            task=task,
            evidence=evidence,
            outcome=outcome,
            flags=flags,
            guidance=guidance,
        )

        # Cap validation fan-out: the LLM solver tends to produce both real
        # candidates and several echoed-source noise lines.  Beyond ~3 the
        # planner just spends cycles confirming "not the flag" — and any real
        # candidate sorts towards the front because :class:`SolverResultParser`
        # merges decoded streams (most reliable) before plugin candidates.
        capped_real = flags.flag_candidates[:3]
        capped_near_miss = flags.cleaned_near_miss[:2]
        new_tasks = build_flag_validation_tasks(
            capped_real, source="solver_execution"
        )
        new_tasks.extend(
            build_flag_validation_tasks(
                capped_near_miss, source="solver_near_miss_cleaned"
            )
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
        worker_notes.extend(worker_lint_notes)
        if guidance.reasoning:
            worker_notes.append(f"Reasoning: {guidance.reasoning[:300]}")
        worker_notes.extend(retry_plan.notes)
        if flags.cleaned_near_miss:
            worker_notes.append(
                f"Auto-cleaned {len(flags.cleaned_near_miss)} near-miss candidate(s) "
                f"for validation: {flags.cleaned_near_miss[:3]}"
            )

        bundle = outcome.bundle
        # ``retryable`` is intentionally always ``False``: solver retries are
        # handled by :class:`SolverRetryPolicy`, which spawns a NEW task with
        # a concrete failure fingerprint in ``previous_attempts``.  Allowing
        # the orchestrator to re-dispatch the same task_id would burn an extra
        # LLM call to regenerate solver code with no new context, which we
        # measured to be the dominant cost of failed-solver runs.
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
            retryable=False,
        )

    def _generate_lint_clean_solver_code(
        self,
        evidence: SolverEvidence,
    ) -> tuple[SolverCodeGuidance, int]:
        """Call the LLM until it produces solver_code that passes static lint.

        Returns ``(guidance, lint_failures_observed)``.  Re-prompts up to
        :data:`_LINT_RETRY_BUDGET` times on lint failures, with the concrete
        :class:`SolverLintResult` fingerprint folded into the next user
        prompt as ``CRITICAL_LINT_FAILURE``.  When the budget is exhausted
        we raise :class:`LLMClientError` so the orchestrator can spawn a
        fresh retry task — this is cheaper than running broken code in
        the container and waiting for the runtime ``SyntaxError``.
        """
        sys_p, base_user_p = self.prompt_builder.build(evidence)
        last_lint: SolverLintResult | None = None
        for attempt in range(_LINT_RETRY_BUDGET + 1):
            user_p = base_user_p
            if last_lint is not None:
                user_p = self._append_lint_block(base_user_p, last_lint)

            guidance = self.generate_structured_output(
                system_prompt=sys_p,
                user_prompt=user_p,
                schema=SolverCodeGuidance,
                temperature=0.3,
            )
            if not guidance.solver_code.strip():
                # Treat as the same class of failure: the LLM's structured
                # output passed pydantic but produced an empty body.  Fall
                # through to lint, which will report ``error_kind="empty"``.
                pass

            lint = lint_solver_code(guidance.solver_code, guidance.solver_language)
            if lint.ok:
                return guidance, attempt
            last_lint = lint

        assert last_lint is not None
        raise LLMClientError(
            "LLM solver_code failed in-process lint after "
            f"{_LINT_RETRY_BUDGET + 1} attempt(s): {last_lint.fingerprint()}",
            transient=True,
        )

    @staticmethod
    def _append_lint_block(base_user_prompt: str, lint: SolverLintResult) -> str:
        """Append a ``CRITICAL_LINT_FAILURE`` block to the user prompt.

        The block carries the offending line + line number when known so
        the LLM can fix the *specific* bug instead of restarting from
        scratch.  We deliberately reuse the JSON-block style of the rest
        of the user prompt (built by :class:`SolverPromptBuilder`) so the
        LLM treats it as another structured input field.
        """
        block: dict[str, object] = {
            "CRITICAL_LINT_FAILURE": {
                "error_kind": lint.error_kind,
                "error_message": lint.error_message,
                "instruction": (
                    "Your previous solver_code failed local Python lint "
                    "BEFORE we executed it in the container.  Re-emit the "
                    "FULL corrected script — do not return a diff or a "
                    "partial fix."
                ),
            }
        }
        critical = block["CRITICAL_LINT_FAILURE"]
        assert isinstance(critical, dict)
        if lint.offending_lineno is not None:
            critical["offending_lineno"] = lint.offending_lineno
        if lint.offending_line:
            critical["offending_line"] = lint.offending_line[:200]
        if lint.error_kind == "syntax":
            critical["correction_hint"] = (
                "Most common causes: unbalanced parentheses/brackets, "
                "indentation that mixes tabs and spaces, unterminated "
                "string literal, stray colon, or a stray triple-backtick "
                "fence inside the code."
            )
        elif lint.error_kind == "missing_import":
            critical["correction_hint"] = (
                "Add the missing ``import`` line at the top of the "
                "script.  In particular: ``import sys`` if you use "
                "sys.exit / sys.stderr / sys.argv anywhere; ``import os`` "
                "for os.chdir / os.environ; ``import subprocess`` for "
                "subprocess.run; ``import re`` for re.search/findall."
            )
        elif lint.error_kind == "empty":
            critical["correction_hint"] = (
                "Emit a complete runnable Python script in the "
                "``solver_code`` field — empty or whitespace-only output "
                "is rejected and wastes a cycle."
            )
        return base_user_prompt + "\n\n" + json.dumps(block, ensure_ascii=True, indent=2)

    @staticmethod
    def _resolve_timeout(task: Task, category: str) -> int:
        default_timeout = _CATEGORY_TIMEOUT.get(category, 60)
        return int(task.input_context.get("solver_timeout_s", default_timeout))
