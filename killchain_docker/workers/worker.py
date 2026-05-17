"""Unified Worker class with injected Persona strategy.

The execution loop is shared; persona differences (capabilities, routing
summary, metadata preparation) live in the PersonaSpec or custom hooks.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from pydantic import BaseModel

from killchain_docker.llm import LLMClient
from killchain_docker.orchestrator.policy import CandidatePolicy
from killchain_docker.reasoning.flag import encoding_cascade
from killchain_docker.state import (
    Asset,
    AssetKind,
    FlagCandidate,
    Hypothesis,
    RunState,
    Service,
    StateDelta,
    TodoItem,
    WorkerResult,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools.core import _strings
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.protocols import Persona, PersonaSpec
from killchain_docker.workers.tool_metadata import normalize_tool_metadata

log = logging.getLogger(__name__)


class _FlagMatchVerdict(BaseModel):
    """LLM verdict on whether two flag strings are semantically equivalent."""
    equivalent: bool
    reason: str = ""


_FLAG_MATCH_SYSTEM_PROMPT = """\
You are a CTF flag validator. Given a candidate string and the expected flag, \
determine if they represent the same flag value despite possible formatting differences.

Common format variations:
- Different bracket/prefix styles: `{key: VALUE}` vs `key{VALUE}`
- Whitespace/punctuation around delimiters: `{key: X}` vs `key{X}`
- Wrapping differences: bare body vs prefix{body}
- Case-insensitive prefix: `KEY{x}` vs `key{x}`
- Extra surrounding context stripped away

Return equivalent=true ONLY if the core flag content is identical (the meaningful \
secret value is the same). Do NOT return true for completely different values."""


def _tool_success(capability: ToolCapability, bundle, output_context: dict[str, object]) -> bool:
    if bundle.result.exit_code not in (None, 0):
        return False
    if capability == ToolCapability.SCRIPT_EXEC:
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
    if any(token in text for token in ("recover", "decrypt", "decode", "find", "print", "output")):
        if "flag" in text or "plaintext" in text or "readable ascii" in text:
            return True
    if "output contains" in text and ("flag{" in text or "ctf{" in text):
        return True
    return False


class Worker(WorkerAgent):
    """Unified worker driven by an injected Persona strategy."""

    _MAX_INNER_STEPS = 15
    _MAX_METADATA_RETRIES = 2

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
    def allowed_capabilities(self) -> tuple[ToolCapability, ...]:
        return self._persona.allowed_capabilities

    def supports(self, todo: TodoItem) -> bool:
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
                    capability, selected_metadata, rationale, hypothesis_text, mem_updates = self._choose_capability(
                        task, state, prior_steps=prior_steps if prior_steps else None
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
                    bundle = self.run_capability(
                        task=task, capability=capability,
                        metadata=metadata, timeout_s=timeout_s,
                    )
                    break
                except (ToolExecutionError, ValueError) as exc:
                    metadata_retries += 1
                    if metadata_retries > self._MAX_METADATA_RETRIES:
                        return WorkerResult(
                            todo_id=task.todo_id, worker_name=self.name,
                            success=False,
                            summary=f"{self.name} failed to execute its selected tool: {exc}",
                            error=str(exc), retryable=False,
                        )
                    cap_str = capability.value if capability and hasattr(capability, "value") else str(capability or "unknown")
                    prior_steps.append({
                        "step": step, "capability": cap_str, "rationale": rationale,
                        "summary": f"VALIDATION ERROR: {exc}",
                        "flag_candidates": [], "stdout_preview": "",
                        "stderr_preview": str(exc), "returncode": -1,
                        "failure_kind": "metadata_validation", "failure_detail": str(exc),
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
                "stdout_preview": str(output_context.get("stdout", ""))[:2000],
                "stderr_preview": str(output_context.get("stderr", ""))[:1500],
                "returncode": output_context.get("returncode"),
                "failure_kind": output_context.get("failure_kind"),
                "failure_detail": output_context.get("failure_detail"),
            })

            if bundle.state_delta.flag_candidates:
                break
            if step == self._MAX_INNER_STEPS - 1:
                break
            if not self._should_continue(task, state, prior_steps):
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
        if accumulated_memory:
            result.memory_updates = accumulated_memory

        # Recon persona: inject seed asset on success
        if self._persona.name == "recon-worker":
            self._inject_recon_asset(task, state, result)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

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
        if (
            capability == ToolCapability.SCRIPT_EXEC
            and success and not flag_values
            and _is_flag_recovery_task(todo)
        ):
            has_near_miss = bool(output_context.get("near_miss_candidates"))
            if not has_near_miss:
                partial = True
                partial_reason = (
                    str(output_context.get("partial_reason") or "").strip()
                    or "script completed for a flag-recovery task but produced no flag candidate"
                )
                result_quality = result_quality or "partial_no_candidate"
            else:
                result_quality = result_quality or "near_miss"
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
            retryable=False if partial else not success,
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
                    FlagCandidate(value=c, source="flag-validation", confidence=0.1, validated=False, rejected_reason="candidate mismatch")
                    for c in candidates[:12]
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
        # LLM fallback for format variants (e.g. "{key: VALUE}" vs "key{VALUE}")
        return self._llm_flag_matches(c, e)

    def _llm_flag_matches(self, candidate: str, expected: str) -> bool:
        """Use LLM to judge whether candidate and expected are the same flag."""
        if self.llm_client is None:
            return False
        try:
            verdict = self.llm_client.generate_json(
                system_prompt=_FLAG_MATCH_SYSTEM_PROMPT,
                user_prompt=f"Candidate: {candidate}\nExpected:  {expected}",
                schema=_FlagMatchVerdict,
                temperature=0.0,
            )
            if verdict.equivalent:
                log.info(
                    "LLM flag match accepted: candidate=%r expected=%r reason=%s",
                    candidate, expected, verdict.reason,
                )
            return verdict.equivalent
        except Exception as exc:
            log.debug("LLM flag match fallback failed: %s", exc)
            return False


__all__ = ["Worker"]
