"""High-level persona workers for the planner-router runtime."""

from __future__ import annotations

from urllib.parse import urlparse

from killchain_docker.llm import LLMClient
from killchain_docker.orchestrator.policy import CandidatePolicy
from killchain_docker.state import (
    Asset,
    AssetKind,
    FlagCandidate,
    RunState,
    Service,
    StateDelta,
    TodoItem,
    WorkerResult,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools.core import _strings
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec
from killchain_docker.workers.tool_metadata import normalize_tool_metadata


def _tool_success(capability: ToolCapability, bundle, output_context: dict[str, object]) -> bool:
    if bundle.result.exit_code not in (None, 0):
        return False
    if capability == ToolCapability.SCRIPT_EXECUTE:
        returncode = output_context.get("returncode")
        if returncode not in (None, ""):
            try:
                return int(returncode) == 0
            except (TypeError, ValueError):
                return False
    return True


def _is_flag_recovery_task(todo: TodoItem) -> bool:
    text = " ".join(
        [
            todo.goal,
            " ".join(todo.success_criteria),
            " ".join(todo.constraints),
        ]
    ).lower()
    if "flag candidate" in text or "candidate flag" in text:
        return True
    if any(token in text for token in ("recover", "decrypt", "decode", "find", "print", "output")):
        if "flag" in text or "plaintext" in text or "readable ascii" in text:
            return True
    if "output contains" in text and ("flag{" in text or "ctf{" in text):
        return True
    return False


class PersonaWorker(WorkerAgent):
    """Base class for high-level workers that choose and run tool capabilities."""

    allowed_capabilities: tuple[ToolCapability, ...] = ()

    def supports(self, todo: TodoItem) -> bool:
        del todo
        return True

    def _choose_capability(self, todo: TodoItem, state: RunState) -> tuple[ToolCapability, dict[str, object], str]:
        decision = self.choose_tool_use(
            task=todo,
            state=state,
            allowed_capabilities=list(self.allowed_capabilities),
        )
        return (
            ToolCapability(decision.capability),
            dict(decision.metadata),
            decision.rationale,
        )

    def _prepare_metadata(
        self,
        *,
        capability: ToolCapability,
        todo: TodoItem,
        state: RunState,
        selected_metadata: dict[str, object],
    ) -> dict[str, object]:
        return normalize_tool_metadata(
            capability,
            todo,
            state,
            selected_metadata,
        )

    def _result_from_bundle(
        self,
        *,
        todo: TodoItem,
        capability: ToolCapability,
        output_context: dict[str, object],
        summary: str,
        success: bool,
        bundle,
        rationale: str,
    ) -> WorkerResult:
        state_delta = bundle.state_delta
        flag_values = [candidate.value for candidate in state_delta.flag_candidates]
        partial = False
        partial_reason = None
        result_quality = str(output_context.get("result_quality") or "")
        if (
            capability == ToolCapability.SCRIPT_EXECUTE
            and success
            and not flag_values
            and _is_flag_recovery_task(todo)
        ):
            partial = True
            partial_reason = (
                str(output_context.get("partial_reason") or "").strip()
                or "script completed for a flag-recovery task but produced no flag candidate"
            )
            result_quality = result_quality or "partial_no_candidate"
            output_context["result_quality"] = result_quality
            output_context["partial_reason"] = partial_reason
        output_context["worker_rationale"] = rationale
        output_context["capability"] = capability.value
        return WorkerResult(
            todo_id=todo.todo_id,
            worker_name=self.name,
            success=success,
            summary=summary,
            output_context=output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            state_delta=state_delta,
            evidence_updates=[bundle.evidence],
            notes=list(bundle.parsed.notes),
            retryable=False if partial else not success,
            partial=partial,
            result_quality=result_quality or None,
            partial_reason=partial_reason,
        )

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        if self.tool_gateway is None:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} cannot run because no tool gateway is configured.",
                error="tool gateway unavailable",
                retryable=False,
            )
        try:
            capability, selected_metadata, rationale = self._choose_capability(task, state)
            metadata = self._prepare_metadata(
                capability=capability,
                todo=task,
                state=state,
                selected_metadata=selected_metadata,
            )
            timeout_raw = metadata.pop("timeout_s", None)
            timeout_s = int(timeout_raw) if timeout_raw not in (None, "") else None
            bundle = self.run_capability(
                task=task,
                capability=capability,
                metadata=metadata,
                timeout_s=timeout_s,
            )
        except (ToolExecutionError, ValueError) as exc:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} failed to execute its selected tool: {exc}",
                error=str(exc),
                retryable=False,
            )

        output_context = dict(bundle.parsed.output_context)
        success = _tool_success(capability, bundle, output_context)
        return self._result_from_bundle(
            todo=task,
            capability=capability,
            output_context=output_context,
            summary=bundle.parsed.summary,
            success=success,
            bundle=bundle,
            rationale=rationale,
        )


class ReconWorker(PersonaWorker):
    """Persona worker for scope mapping and service discovery."""

    name = "recon-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Maps authorized scope into assets and collects first-pass host or HTTP metadata."
    allowed_capabilities = (
        ToolCapability.HTTP_METADATA,
        ToolCapability.HOST_INVENTORY,
        ToolCapability.HOST_BANNER,
    )

    def _prepare_metadata(
        self,
        *,
        capability: ToolCapability,
        todo: TodoItem,
        state: RunState,
        selected_metadata: dict[str, object],
    ) -> dict[str, object]:
        metadata = super()._prepare_metadata(
            capability=capability,
            todo=todo,
            state=state,
            selected_metadata=selected_metadata,
        )
        scope = str(metadata.get("scope") or (state.authorized_scope[0] if state.authorized_scope else ""))
        parsed = urlparse(scope)
        asset_id = str(metadata.get("asset_id") or "seed-asset")
        if parsed.scheme in {"http", "https"}:
            metadata.setdefault("base_url", scope)
            metadata.setdefault("hostname", parsed.hostname or "")
        else:
            metadata.setdefault("hostname", parsed.hostname or scope)
        metadata.setdefault("asset_id", asset_id)
        return metadata

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        result = super().run(task, state)
        scope = str(task.context.get("scope") or (state.authorized_scope[0] if state.authorized_scope else ""))
        parsed = urlparse(scope)
        if result.success and scope and parsed.scheme in {"http", "https"}:
            asset_id = str(task.context.get("asset_id") or "seed-asset")
            asset = Asset(
                asset_id=asset_id,
                kind=AssetKind.WEB_APPLICATION,
                hostname=parsed.hostname,
                base_url=scope,
                services=[Service(port=parsed.port or (443 if parsed.scheme == "https" else 80), name=parsed.scheme)],
                tags={"seed", "recon"},
            )
            result.asset_updates.append(asset)
        return result


class ArtifactWorker(PersonaWorker):
    """Persona worker for local challenge-file analysis."""

    name = "artifact-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Inspects bundled files, source, binaries, archives, repositories, databases, and packet captures."
    preferred_challenge_categories = ("crypto", "rev", "forensics", "misc", "pwn", "web")
    allowed_capabilities = (
        ToolCapability.ARTIFACT_TRIAGE,
        ToolCapability.ARTIFACT_SOURCE,
        ToolCapability.ARTIFACT_BINARY_TRIAGE,
        ToolCapability.ARTIFACT_BINARY_DISASSEMBLE,
        ToolCapability.ARTIFACT_BINARY_EXECUTE,
        ToolCapability.ARTIFACT_ARCHIVE,
        ToolCapability.ARTIFACT_SQLITE,
        ToolCapability.ARTIFACT_PCAP,
        ToolCapability.ARTIFACT_REPO,
        ToolCapability.ARTIFACT_RUNTIME,
        ToolCapability.ARTIFACT_COMPUTATION,
        ToolCapability.SCRIPT_EXECUTE,
        ToolCapability.FLAG_HARVEST,
    )


class WebWorker(PersonaWorker):
    """Persona worker for HTTP content, paths, and forms."""

    name = "web-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Reviews HTTP content, probes routes, and interacts with discovered forms inside authorized scope."
    preferred_challenge_categories = ("web",)
    allowed_capabilities = (
        ToolCapability.HTTP_METADATA,
        ToolCapability.HTTP_CONTENT,
        ToolCapability.HTTP_PROBE_PATHS,
        ToolCapability.HTTP_FORM_PROBE,
        ToolCapability.CREDENTIAL_LOGIN,
    )


class ExploitWorker(PersonaWorker):
    """Persona worker for vulnerability probes and exploit experiments."""

    name = "exploit-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Runs bounded exploit, credential, vulnerability, and script experiments from accumulated evidence."
    allowed_capabilities = (
        ToolCapability.VULN_SCAN,
        ToolCapability.EXPLOIT_PROBE,
        ToolCapability.CREDENTIAL_LOGIN,
        ToolCapability.SCRIPT_EXECUTE,
    )


class FlagWorker(PersonaWorker):
    """Persona worker for final flag hunting and validation."""

    name = "flag-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Harvests and validates concrete flag candidates."
    allowed_capabilities = (
        ToolCapability.FLAG_HARVEST,
        ToolCapability.SCRIPT_EXECUTE,
    )

    def __init__(
        self,
        *,
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
        self.expected_flag = expected_flag

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        candidates = [
            candidate
            for candidate in _strings(task.context.get("candidate_flag"))
            if CandidatePolicy.accepts_for_state(state, candidate)
        ]
        if not candidates:
            candidates = [candidate.value for candidate in CandidatePolicy.validation_ready_candidates(state)]
        for candidate in candidates:
            if self.expected_flag and candidate == self.expected_flag:
                return WorkerResult(
                    todo_id=task.todo_id,
                    worker_name=self.name,
                    success=True,
                    summary=f"Validated flag candidate {candidate}.",
                    state_delta=StateDelta(
                        flag_candidates=[
                            FlagCandidate(
                                value=candidate,
                                source="flag-validation",
                                confidence=1.0,
                                validated=True,
                            )
                        ]
                    ),
                    solved=True,
                    validated_flag=candidate,
                    notes=[f"{self.name} validated the final flag."],
                )
        if candidates and self.expected_flag:
            return WorkerResult(
                todo_id=task.todo_id,
                worker_name=self.name,
                success=False,
                summary="Flag candidates were tested but did not match the expected flag.",
                state_delta=StateDelta(
                    flag_candidates=[
                        FlagCandidate(
                            value=candidate,
                            source="flag-validation",
                            confidence=0.1,
                            validated=False,
                            rejected_reason="candidate mismatch",
                        )
                        for candidate in candidates[:12]
                    ]
                ),
                error="candidate mismatch",
                retryable=False,
            )
        return super().run(task, state)


def _flag_factory(context: WorkerBuildContext) -> FlagWorker:
    return FlagWorker(
        llm_client=context.llm_client,
        execution_plane=context.execution_plane,
        expected_flag=context.expected_flag,
    )


WORKER_SPECS: tuple[WorkerSpec, ...] = (
    WorkerSpec("ReconWorker", "persona", lambda ctx: ReconWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), ReconWorker.routing_summary),
    WorkerSpec("ArtifactWorker", "persona", lambda ctx: ArtifactWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), ArtifactWorker.routing_summary),
    WorkerSpec("WebWorker", "persona", lambda ctx: WebWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), WebWorker.routing_summary),
    WorkerSpec("ExploitWorker", "persona", lambda ctx: ExploitWorker(llm_client=ctx.llm_client, execution_plane=ctx.execution_plane), ExploitWorker.routing_summary),
    WorkerSpec("FlagWorker", "persona", _flag_factory, FlagWorker.routing_summary),
)
