"""Unified Worker class with injected Persona strategy.

The execution loop is shared; persona differences (capabilities, routing
summary, metadata preparation) live in the PersonaSpec or custom hooks.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from killchain_docker.llm import LLMClient
from killchain_docker.orchestrator.policy import CandidatePolicy, TodoPolicy
from killchain_docker.reasoning.flag import encoding_cascade
from killchain_docker.state import (
    Asset,
    AssetKind,
    DispatchIntent,
    FlagCandidate,
    Hypothesis,
    RunState,
    Service,
    StateDelta,
    TodoItem,
    TodoPhase,
    WorkerResult,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools import ToolOutputStatus
from killchain_docker.tools.core import _strings
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.protocols import Persona, PersonaSpec
from killchain_docker.workers.tool_metadata import normalize_tool_metadata

_INFRASTRUCTURE_FAILURE_KINDS = frozenset({"infrastructure_error"})
_SCRIPT_REPAIRABLE_FAILURE_KINDS = frozenset({
    "binary_structure_error",
    "bytes_text_mismatch",
    "parse_error",
    "path_resolution_error",
    "path_type_mismatch",
    "scope_violation_blocked",
    "syntax_error",
    "timeout",
    "type_error",
    "unbounded_loop_guard",
    "undefined_name",
})


def _tool_success(capability: ToolCapability, bundle, output_context: dict[str, object]) -> bool:
    if bundle.tool_output.status != ToolOutputStatus.SUCCESS:
        return False
    if capability != ToolCapability.SCRIPT_EXEC:
        return True
    if bundle.result.exit_code not in (None, 0):
        return False
    returncode = output_context.get("returncode")
    if returncode not in (None, ""):
        try:
            return int(returncode) == 0
        except (TypeError, ValueError):
            return False
    return True


def _is_flag_recovery_task(todo: TodoItem) -> bool:
    text = " ".join([todo.goal, " ".join(todo.success_criteria), " ".join(todo.constraints)]).lower()
    if "flag candidate" in text or "candidate flag" in text:
        return True
    if "flag format" in text or "flag pattern" in text:
        return True
    if re.search(r"\b(recover|derive|find|print|extract|decrypt|decode)\s+(?:the\s+)?flag\b", text):
        return True
    if any(token in text for token in ("recover", "decrypt", "decode", "print", "output")):
        if "plaintext" in text or "readable ascii" in text:
            return True
    if "output contains" in text and ("flag{" in text or "ctf{" in text):
        return True
    return False


def _is_execution_closure_task(todo: TodoItem) -> bool:
    """Return true for CTF tasks expected to close artifact-to-answer gaps."""

    if _is_flag_recovery_task(todo):
        return True
    context_text = " ".join(str(value) for value in (todo.context or {}).values())
    text = " ".join([
        todo.goal,
        " ".join(todo.success_criteria),
        " ".join(todo.constraints),
        context_text,
    ]).lower()
    action_terms = (
        "carve", "decode", "decrypt", "derive", "extract", "find", "inspect",
        "parse", "print", "read", "recover", "reconstruct", "search",
    )
    target_terms = (
        "artifact", "barcode", "embedded", "file", "flag", "hidden", "image",
        "jpg", "jpeg", "key", "password", "plaintext", "png", "qr", "secret",
        "stego", "token", "transferred file",
    )
    return any(term in text for term in action_terms) and any(
        term in text for term in target_terms
    )


def _returncode_failed(value: object) -> bool:
    if value in (None, "", 0):
        return False
    try:
        return int(value) != 0
    except (TypeError, ValueError):
        return True


class Worker(WorkerAgent):
    """Unified worker driven by an injected Persona strategy."""

    _MAX_INNER_STEPS = 3
    _MAX_METADATA_RETRIES = 1

    def __init__(
        self,
        *,
        persona: PersonaSpec | Persona,
        llm_client: LLMClient | None = None,
        execution_plane=None,
        tool_gateway=None,
        expected_flag: str | None = None,
    ) -> None:
        super().__init__(
            llm_client=llm_client,
            execution_plane=execution_plane,
            tool_gateway=tool_gateway,
        )
        self._persona = persona
        self.expected_flag = expected_flag

    # Delegate persona properties
    @property
    def name(self) -> str:  # type: ignore[override]
        return self._persona.name

    @name.setter
    def name(self, value: str) -> None:
        pass  # WorkerAgent sets name as class var; ignore

    @property
    def supported_todo_kinds(self) -> tuple[str, ...]:  # type: ignore[override]
        return self._persona.supported_todo_kinds

    @property
    def routing_summary(self) -> str:  # type: ignore[override]
        return self._persona.routing_summary

    @property
    def preferred_challenge_categories(self) -> tuple[str, ...]:  # type: ignore[override]
        return self._persona.preferred_challenge_categories

    @property
    def required_context_keys(self) -> tuple[str, ...]:  # type: ignore[override]
        return self._persona.required_context_keys

    @property
    def supported_dispatch_profiles(self) -> tuple[str, ...]:  # type: ignore[override]
        return self._persona.supported_dispatch_profiles

    @property
    def allowed_capabilities(self) -> tuple[ToolCapability, ...]:
        return self._persona.allowed_capabilities

    def supports(self, todo: TodoItem) -> bool:
        if self._persona.name == "flag-worker":
            return todo.phase == TodoPhase.FLAG_VALIDATION
        return True

    # ------------------------------------------------------------------
    # Core execution loop (shared across all personas)
    # ------------------------------------------------------------------

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        # Flag worker fast-path: validate candidates without tool execution
        if self._persona.name == "flag-worker":
            result = self._try_flag_validation(task, state)
            if result is not None:
                return result

        if self.tool_gateway is None:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} cannot run because no tool gateway is configured.",
                error="tool gateway unavailable",
                retryable=False,
            )

        directed_result = self._run_direct_capability_hint(task, state)
        if directed_result is not None:
            return directed_result

        prior_steps: list[dict[str, object]] = []
        last_bundle = None
        last_capability = None
        last_rationale = ""
        accumulated_hypotheses: list[Hypothesis] = []
        accumulated_memory: dict[str, str] = {}

        for step in range(self._MAX_INNER_STEPS):
            metadata_retries = 0
            bundle = None
            capability = None
            rationale = ""
            while True:
                try:
                    fixed_capability = self._fixed_llm_capability(task)
                    if fixed_capability is not None:
                        self.report_progress(
                            state,
                            task,
                            f"{self.name} preparing {fixed_capability.value} for step {step + 1}",
                        )
                        capability, selected_metadata, rationale, hypothesis_text, mem_updates = self._choose_fixed_capability(
                            fixed_capability,
                            task,
                            state,
                            prior_steps=prior_steps if prior_steps else None,
                        )
                    else:
                        self.report_progress(
                            state,
                            task,
                            f"{self.name} choosing tool for step {step + 1}",
                        )
                        capability, selected_metadata, rationale, hypothesis_text, mem_updates = self._choose_capability(
                            task, state, prior_steps=prior_steps if prior_steps else None
                        )
                    self.report_progress(
                        state,
                        task,
                        f"{self.name} selected {capability.value} for step {step + 1}",
                    )
                    if hypothesis_text:
                        accumulated_hypotheses.append(Hypothesis(title=hypothesis_text))
                    if mem_updates:
                        accumulated_memory.update(mem_updates)
                    metadata = self._prepare_metadata(
                        capability=capability, todo=task, state=state,
                        selected_metadata=selected_metadata,
                    )
                    timeout_raw = metadata.pop("timeout_s", None)
                    timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
                    self.report_progress(
                        state,
                        task,
                        f"{self.name} executing {capability.value} for step {step + 1}",
                    )
                    bundle = self.run_capability(
                        task=task, capability=capability,
                        metadata=metadata, timeout_s=timeout_s,
                    )
                    self.report_progress(
                        state,
                        task,
                        f"{self.name} completed {capability.value} for step {step + 1}",
                    )
                    if bundle.state_delta.flag_candidates:
                        self.report_flag_candidates(
                            state,
                            task,
                            bundle.state_delta.flag_candidates,
                        )
                    break
                except (ToolExecutionError, ValueError) as exc:
                    error_text = str(exc)
                    failure_kind = self._metadata_failure_kind(error_text, capability)
                    metadata_retries += 1
                    if metadata_retries > self._MAX_METADATA_RETRIES:
                        cap_str = capability.value if capability and hasattr(capability, "value") else str(capability or "unknown")
                        partial = _is_execution_closure_task(task)
                        output_context = {
                            "capability": cap_str,
                            "failure_kind": failure_kind,
                            "failure_detail": error_text,
                            "executed": False,
                        }
                        if partial:
                            output_context["agent_handoff"] = {
                                "reason": "tool_metadata_validation_failed",
                                "target": "planner",
                            }
                        return WorkerResult(
                            todo_id=task.todo_id, worker_name=self.name,
                            success=False,
                            summary=f"{self.name} failed to execute its selected tool: {error_text}",
                            error=error_text, retryable=False,
                            partial=partial,
                            partial_reason=error_text if partial else None,
                            result_quality=failure_kind,
                            output_context=output_context,
                        )
                    cap_str = capability.value if capability and hasattr(capability, "value") else str(capability or "unknown")
                    prior_steps.append({
                        "step": step, "capability": cap_str, "rationale": rationale,
                        "summary": f"VALIDATION ERROR: {error_text}",
                        "flag_candidates": [], "stdout_preview": "",
                        "stderr_preview": error_text, "returncode": -1,
                        "failure_kind": failure_kind, "failure_detail": error_text,
                        "executed": False,
                    })

            last_bundle = bundle
            last_capability = capability
            last_rationale = rationale

            output_context = dict(bundle.tool_output.output_context)
            prior_steps.append({
                "step": step, "capability": capability.value, "rationale": rationale,
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
            })

            if bundle.state_delta.flag_candidates:
                break
            if step == self._MAX_INNER_STEPS - 1:
                break
            if not self._should_continue_after_step(task, prior_steps):
                break

        output_context = dict(last_bundle.tool_output.output_context)
        success = _tool_success(last_capability, last_bundle, output_context)
        if len(prior_steps) > 1:
            output_context["react_steps"] = len(prior_steps)

        # Encoding cascade for near-misses
        cascade_candidates: list[FlagCandidate] = []
        if not last_bundle.state_delta.flag_candidates:
            near_misses = output_context.get("near_miss_candidates") or []
            for nm in near_misses[:3]:
                for transformed in encoding_cascade(str(nm)):
                    if CandidatePolicy.accepts_for_state(state, transformed):
                        cascade_candidates.append(
                            FlagCandidate(value=transformed, source="encoding_cascade", confidence=0.2)
                        )

        result = self._result_from_bundle(
            todo=task, capability=last_capability, output_context=output_context,
            summary=last_bundle.tool_output.summary, success=success,
            bundle=last_bundle, rationale=last_rationale,
        )
        if cascade_candidates:
            existing = list(result.state_delta.flag_candidates) if result.state_delta else []
            result.state_delta = StateDelta(**{**result.state_delta.model_dump(), "flag_candidates": existing + cascade_candidates})
        if accumulated_hypotheses:
            existing = list(result.state_delta.hypotheses) if result.state_delta else []
            result.state_delta = StateDelta(**{**result.state_delta.model_dump(), "hypotheses": existing + accumulated_hypotheses})
        memory_updates = self._trusted_memory_updates(task, result, accumulated_memory)
        if memory_updates:
            result.memory_updates = memory_updates

        # Recon persona: inject seed asset on success
        if self._persona.name == "recon-worker":
            self._inject_recon_asset(task, state, result)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _trusted_memory_updates(
        todo: TodoItem,
        result: WorkerResult,
        updates: dict[str, str],
    ) -> dict[str, str]:
        """Persist only facts backed by a completed, useful worker result."""

        if not updates or not result.success or result.partial:
            return {}
        blocked_quality = {
            "partial_no_candidate",
            "script_failed",
            "timeout",
            "unbounded_loop_guard",
            "syntax_error",
            "parse_error",
            "binary_structure_error",
            "undefined_name",
            "type_error",
            "no_candidate",
        }
        if str(result.result_quality or "").strip().lower() in blocked_quality:
            return {}
        has_candidates = bool(result.state_delta and result.state_delta.flag_candidates)
        if _is_execution_closure_task(todo) and not has_candidates:
            return {}
        return updates

    @staticmethod
    def _should_continue_after_step(task: TodoItem, prior_steps: list[dict[str, object]]) -> bool:
        """Deterministic inner-loop policy.

        Validation retries may happen before execution. After the first
        executed script fails with a repairable Python/runtime error, allow one
        bounded LLM/tool repair step with the raw traceback in prior context.
        Near-miss and no-candidate evidence still returns to the planner for an
        explicit follow-up todo.
        """
        executed_steps = [
            step for step in prior_steps
            if step.get("executed") is not False
        ]
        if len(executed_steps) >= min(2, Worker._MAX_INNER_STEPS):
            return False
        last = prior_steps[-1] if prior_steps else {}
        if last.get("flag_candidates"):
            return False
        if last.get("capability") != ToolCapability.SCRIPT_EXEC.value:
            return False
        failure_kind = str(last.get("failure_kind") or "").strip()
        if failure_kind in _INFRASTRUCTURE_FAILURE_KINDS:
            return False
        if failure_kind not in _SCRIPT_REPAIRABLE_FAILURE_KINDS:
            return False
        return _returncode_failed(last.get("returncode"))

    def _choose_capability(
        self, todo: TodoItem, state: RunState, prior_steps: list[dict[str, object]] | None = None,
    ) -> tuple[ToolCapability, dict[str, object], str, str | None, dict[str, str]]:
        decision = self.choose_tool_use(
            task=todo, state=state,
            allowed_capabilities=list(self.allowed_capabilities),
            prior_steps=prior_steps,
        )
        return (
            ToolCapability(decision.capability),
            dict(decision.metadata),
            decision.rationale,
            decision.hypothesis,
            dict(decision.memory_updates) if decision.memory_updates else {},
        )

    def _choose_fixed_capability(
        self,
        capability: ToolCapability,
        todo: TodoItem,
        state: RunState,
        prior_steps: list[dict[str, object]] | None = None,
    ) -> tuple[ToolCapability, dict[str, object], str, str | None, dict[str, str]]:
        decision = self.choose_fixed_tool_use(
            task=todo,
            state=state,
            capability=capability,
            prior_steps=prior_steps,
        )
        return (
            capability,
            dict(decision.metadata),
            decision.rationale,
            decision.hypothesis,
            dict(decision.memory_updates) if decision.memory_updates else {},
        )

    def _fixed_llm_capability(self, todo: TodoItem) -> ToolCapability | None:
        intent = DispatchIntent.from_context(todo.context)
        raw = str(intent.required_capability or todo.context.get("capability_hint") or "").strip()
        if not raw:
            return None
        try:
            capability = ToolCapability(raw)
        except ValueError:
            return None
        if capability not in {ToolCapability.SCRIPT_EXEC, ToolCapability.SHELL_EXEC}:
            return None
        if capability not in self.allowed_capabilities:
            return None
        return capability

    def _run_direct_capability_hint(
        self,
        task: TodoItem,
        state: RunState,
    ) -> WorkerResult | None:
        intent = DispatchIntent.from_context(task.context)
        hint = str(task.context.get("capability_hint") or "").strip()
        direct_capabilities = {
            ToolCapability.ARTIFACT_TRIAGE,
            ToolCapability.DISK_EXTRACT,
            ToolCapability.OFFICE_INSPECT,
            ToolCapability.MEDIA_SCAN,
            ToolCapability.PNG_INSPECT,
        }
        try:
            capability = ToolCapability(hint)
        except ValueError:
            return None
        if (
            capability == ToolCapability.ARTIFACT_TRIAGE
            and not self._artifact_triage_hint_is_direct(task)
        ):
            return None
        if intent.required_capability and intent.required_capability != capability.value:
            return None
        if capability not in direct_capabilities:
            return None
        if capability not in self.allowed_capabilities:
            return None
        rationale = f"deterministic {capability.value} fast path"
        try:
            self.report_progress(
                state,
                task,
                f"{self.name} selected {capability.value} from task capability hint",
            )
            metadata = self._prepare_metadata(
                capability=capability,
                todo=task,
                state=state,
                selected_metadata={},
            )
            timeout_raw = metadata.pop("timeout_s", None)
            timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
            self.report_progress(
                state,
                task,
                f"{self.name} executing {capability.value}",
            )
            bundle = self.run_capability(
                task=task,
                capability=capability,
                metadata=metadata,
                timeout_s=timeout_s,
            )
            self.report_progress(
                state,
                task,
                f"{self.name} completed {capability.value}",
            )
        except (ToolExecutionError, ValueError) as exc:
            error_text = str(exc)
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} failed deterministic {capability.value}: {error_text}",
                error=error_text,
                retryable=False,
                result_quality=self._metadata_failure_kind(error_text, capability),
                output_context={
                    "capability": capability.value,
                    "failure_kind": self._metadata_failure_kind(error_text, capability),
                    "failure_detail": error_text,
                    "executed": False,
                },
            )
        if bundle.state_delta.flag_candidates:
            self.report_flag_candidates(
                state,
                task,
                bundle.state_delta.flag_candidates,
            )
        output_context = dict(bundle.tool_output.output_context)
        success = _tool_success(capability, bundle, output_context)
        return self._result_from_bundle(
            todo=task,
            capability=capability,
            output_context=output_context,
            summary=bundle.tool_output.summary,
            success=success,
            bundle=bundle,
            rationale=rationale,
        )

    @staticmethod
    def _artifact_triage_hint_is_direct(task: TodoItem) -> bool:
        context = task.context or {}
        family = str(context.get("family") or "").strip()
        text = " ".join(
            [
                task.goal,
                " ".join(task.success_criteria),
                " ".join(task.constraints),
            ]
        ).lower()
        if family == "artifact-inventory":
            return not TodoPolicy._goal_requires_artifact_extraction(text)
        if family != "artifact-followup":
            return False
        if TodoPolicy._goal_requires_artifact_extraction(text):
            return False
        return any(
            token in text
            for token in (
                "artifact follow-up",
                "classify",
                "deterministic",
                "first-pass",
                "inspect",
                "inventory",
                "scan",
                "triage",
            )
        )

    def _prepare_metadata(
        self, *, capability: ToolCapability, todo: TodoItem, state: RunState,
        selected_metadata: dict[str, object],
    ) -> dict[str, object]:
        metadata = normalize_tool_metadata(capability, todo, state, selected_metadata)
        # Recon persona: inject scope defaults
        if self._persona.name == "recon-worker":
            scope = str(metadata.get("scope") or (state.authorized_scope[0] if state.authorized_scope else ""))
            parsed = urlparse(scope)
            if parsed.scheme in {"http", "https"}:
                metadata.setdefault("base_url", scope)
                metadata.setdefault("hostname", parsed.hostname or "")
            else:
                metadata.setdefault("hostname", parsed.hostname or scope)
            metadata.setdefault("asset_id", str(metadata.get("asset_id") or "seed-asset"))
        return metadata

    @staticmethod
    def _metadata_failure_kind(
        message: str,
        capability: ToolCapability | None = None,
    ) -> str:
        return ToolGuardPolicy.metadata_failure_kind(message, capability)

    def _result_from_bundle(
        self, *, todo: TodoItem, capability: ToolCapability,
        output_context: dict[str, object], summary: str, success: bool,
        bundle, rationale: str,
    ) -> WorkerResult:
        state_delta = bundle.state_delta
        flag_values = [candidate.value for candidate in state_delta.flag_candidates]
        partial = False
        partial_reason = None
        result_quality = str(output_context.get("result_quality") or "")
        failure_kind = str(output_context.get("failure_kind") or "").strip()
        if failure_kind in _INFRASTRUCTURE_FAILURE_KINDS:
            output_context["result_quality"] = failure_kind
            output_context["worker_rationale"] = rationale
            output_context["capability"] = capability.value
            return WorkerResult(
                todo_id=todo.todo_id,
                worker_name=self.name,
                success=False,
                summary=summary,
                error=str(output_context.get("failure_detail") or summary),
                output_context=output_context,
                asset_updates=bundle.tool_output.assets,
                finding_updates=bundle.tool_output.findings,
                credential_updates=bundle.tool_output.credentials,
                network_updates=bundle.tool_output.network_edges,
                state_delta=state_delta,
                evidence_updates=[bundle.evidence],
                notes=list(bundle.tool_output.notes),
                retryable=True,
                partial=False,
                result_quality=failure_kind,
            )
        needs_closure = _is_execution_closure_task(todo)
        if (
            capability == ToolCapability.SCRIPT_EXEC
            and success and not flag_values
            and needs_closure
        ):
            has_near_miss = bool(output_context.get("near_miss_candidates"))
            partial = True
            if not has_near_miss:
                partial_reason = (
                    str(output_context.get("partial_reason") or "").strip()
                    or "script completed for a flag-recovery task but produced no flag candidate"
                )
                result_quality = result_quality or "partial_no_candidate"
                output_context["agent_handoff"] = {
                    "reason": "script_exec_completed_without_candidate",
                    "target": "planner",
                }
            else:
                partial_reason = (
                    str(output_context.get("partial_reason") or "").strip()
                    or "script completed with near-miss candidates but no valid flag candidate"
                )
                result_quality = result_quality or "near_miss"
                output_context["agent_handoff"] = {
                    "reason": "script_exec_near_miss_without_candidate",
                    "target": "planner",
                }
            output_context["result_quality"] = result_quality
            output_context["partial_reason"] = partial_reason
        elif (
            capability == ToolCapability.SCRIPT_EXEC
            and not success
            and needs_closure
        ):
            partial = True
            failure_kind = str(output_context.get("failure_kind") or "").strip()
            failure_detail = str(output_context.get("failure_detail") or "").strip()
            partial_reason = failure_detail or failure_kind or "script execution failed before recovering a flag"
            result_quality = result_quality or failure_kind or "script_failed"
            output_context["result_quality"] = result_quality
            output_context["partial_reason"] = partial_reason
        output_context["worker_rationale"] = rationale
        output_context["capability"] = capability.value
        return WorkerResult(
            todo_id=todo.todo_id, worker_name=self.name,
            success=success, summary=summary,
            output_context=output_context,
            asset_updates=bundle.tool_output.assets,
            finding_updates=bundle.tool_output.findings,
            credential_updates=bundle.tool_output.credentials,
            network_updates=bundle.tool_output.network_edges,
            state_delta=state_delta,
            evidence_updates=[bundle.evidence],
            notes=list(bundle.tool_output.notes),
            retryable=False,
            partial=partial, result_quality=result_quality or None,
            partial_reason=partial_reason,
        )

    def _inject_recon_asset(self, task: TodoItem, state: RunState, result: WorkerResult) -> None:
        scope = str(task.context.get("scope") or (state.authorized_scope[0] if state.authorized_scope else ""))
        parsed = urlparse(scope)
        if result.success and scope and parsed.scheme in {"http", "https"}:
            asset_id = str(task.context.get("asset_id") or "seed-asset")
            asset = Asset(
                asset_id=asset_id, kind=AssetKind.WEB_APPLICATION,
                hostname=parsed.hostname, base_url=scope,
                services=[Service(port=parsed.port or (443 if parsed.scheme == "https" else 80), name=parsed.scheme)],
                tags={"seed", "recon"},
            )
            result.asset_updates.append(asset)

    # ------------------------------------------------------------------
    # Flag validation (flag-worker persona)
    # ------------------------------------------------------------------

    def _try_flag_validation(self, task: TodoItem, state: RunState) -> WorkerResult | None:
        """Fast-path flag validation without tool execution."""
        candidates = [
            c for c in _strings(task.context.get("candidate_flag"))
            if CandidatePolicy.accepts_for_state(state, c)
        ]
        if not candidates:
            candidates = [c.value for c in CandidatePolicy.validation_ready_candidates(state)]
        if not candidates:
            return None  # Fall through to normal tool execution

        for candidate in candidates:
            if self.expected_flag and self._flag_matches(candidate, self.expected_flag):
                return WorkerResult(
                    todo_id=task.todo_id, worker_name=self.name,
                    success=True,
                    summary=f"Validated flag candidate {candidate}.",
                    state_delta=StateDelta(flag_candidates=[
                        FlagCandidate(value=candidate, source="flag-validation", confidence=1.0, validated=True)
                    ]),
                    solved=True, validated_flag=self.expected_flag,
                    notes=[f"{self.name} validated the final flag."],
                )

        if self.expected_flag:
            return WorkerResult(
                todo_id=task.todo_id, worker_name=self.name,
                success=False,
                summary="Flag candidates were tested but did not match the expected flag.",
                state_delta=StateDelta(flag_candidates=[
                    FlagCandidate(
                        value=c,
                        source="flag-validation",
                        confidence=0.1,
                        validated=False,
                        rejected_reason="candidate mismatch",
                    )
                    for c in candidates
                ]),
                error="candidate mismatch", retryable=False,
            )
        return None  # No expected flag to validate against; use tools

    @staticmethod
    def _unwrap(s: str) -> str:
        m = re.match(r"[A-Za-z0-9_]+\{(.+)\}\s*$", s, re.DOTALL)
        return m.group(1) if m else s

    @staticmethod
    def _extract_prefix(s: str) -> str | None:
        m = re.match(r"([A-Za-z0-9_]+)\{", s)
        return m.group(1) if m else None

    def _flag_matches(self, candidate: str, expected: str) -> bool:
        c, e = candidate.strip(), expected.strip()
        if c == e:
            return True
        c_inner, e_inner = self._unwrap(c), self._unwrap(e)
        if c_inner == e_inner:
            return True
        if prefix := self._extract_prefix(e):
            if f"{prefix}{{{c}}}" == e:
                return True
        if c_inner.lower() == e_inner.lower():
            return True
        return False


__all__ = ["Worker"]
