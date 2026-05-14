"""High-level persona workers for the planner-router runtime."""

from __future__ import annotations

from urllib.parse import urlparse

from killchain_docker.llm import LLMClient, LLMClientError
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
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.workers.specs import WorkerBuildContext, WorkerSpec


_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"


def _list(value: object) -> list[object]:
    if value in (None, "", [], {}, ()):
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _strings(value: object) -> list[str]:
    result: list[str] = []
    for item in _list(value):
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _flag_candidates_from_context(output_context: dict[str, object]) -> list[str]:
    candidates: list[str] = []
    for key in ("flag_candidates", "potential_flags", "grounded_flag_candidates"):
        for candidate in _strings(output_context.get(key)):
            if candidate not in candidates:
                candidates.append(candidate)
    return candidates[:12]


class PersonaWorker(WorkerAgent):
    """Base class for high-level workers that choose and run tool capabilities."""

    allowed_capabilities: tuple[ToolCapability, ...] = ()
    fallback_capability: ToolCapability | None = None

    def supports(self, todo: TodoItem) -> bool:
        del todo
        return True

    def _choose_capability(self, todo: TodoItem, state: RunState) -> tuple[ToolCapability, dict[str, object], str]:
        if self.llm_client is not None and self.tool_gateway is not None:
            try:
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
            except (LLMClientError, ValueError):
                pass
        capability = self._fallback_capability(todo, state)
        return capability, {}, "Fallback capability selected from todo context."

    def _fallback_capability(self, todo: TodoItem, state: RunState) -> ToolCapability:
        del todo, state
        if self.fallback_capability is None:
            raise ToolExecutionError(f"{self.name} has no fallback capability.")
        return self.fallback_capability

    def _prepare_metadata(
        self,
        *,
        capability: ToolCapability,
        todo: TodoItem,
        state: RunState,
        selected_metadata: dict[str, object],
    ) -> dict[str, object]:
        metadata: dict[str, object] = {
            **selected_metadata,
            **todo.context,
        }
        if capability in {
            ToolCapability.ARTIFACT_TRIAGE,
            ToolCapability.ARTIFACT_ARCHIVE,
            ToolCapability.ARTIFACT_SOURCE,
            ToolCapability.ARTIFACT_RUNTIME,
            ToolCapability.ARTIFACT_COMPUTATION,
            ToolCapability.ARTIFACT_BINARY_TRIAGE,
            ToolCapability.ARTIFACT_BINARY_DISASSEMBLE,
            ToolCapability.ARTIFACT_BINARY_EXECUTE,
            ToolCapability.ARTIFACT_SQLITE,
            ToolCapability.ARTIFACT_PCAP,
            ToolCapability.ARTIFACT_REPO,
            ToolCapability.FLAG_HARVEST,
            ToolCapability.SCRIPT_EXECUTE,
        }:
            metadata.setdefault("files_root", _DEFAULT_FILES_ROOT)
            metadata.setdefault(
                "challenge_files",
                list((state.metadata.get("challenge", {}) or {}).get("files", []) or []),
            )
        state.infer_asset_identity(metadata)
        return metadata

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
        flag_values = _flag_candidates_from_context(output_context)
        state_delta = bundle.state_delta
        for value in flag_values:
            if not any(candidate.value == value for candidate in state_delta.flag_candidates):
                state_delta.flag_candidates.append(
                    FlagCandidate(
                        value=value,
                        source=capability.value,
                        confidence=0.7,
                    )
                )
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
            retryable=not success,
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
            )

        output_context = dict(bundle.parsed.output_context)
        success = bundle.result.exit_code in (None, 0)
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
    fallback_capability = ToolCapability.HTTP_METADATA

    def _fallback_capability(self, todo: TodoItem, state: RunState) -> ToolCapability:
        scope = str(todo.context.get("scope") or (state.authorized_scope[0] if state.authorized_scope else ""))
        parsed = urlparse(scope)
        return ToolCapability.HTTP_METADATA if parsed.scheme in {"http", "https"} else ToolCapability.HOST_INVENTORY

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
    fallback_capability = ToolCapability.ARTIFACT_TRIAGE

    def _fallback_capability(self, todo: TodoItem, state: RunState) -> ToolCapability:
        context = todo.context
        if context.get("source_files"):
            return ToolCapability.ARTIFACT_SOURCE
        if context.get("binary_files"):
            return ToolCapability.ARTIFACT_BINARY_TRIAGE
        if context.get("archive_files"):
            return ToolCapability.ARTIFACT_ARCHIVE
        if context.get("database_files"):
            return ToolCapability.ARTIFACT_SQLITE
        if context.get("pcap_files"):
            return ToolCapability.ARTIFACT_PCAP
        if context.get("repo_paths"):
            return ToolCapability.ARTIFACT_REPO
        return ToolCapability.ARTIFACT_TRIAGE


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
    fallback_capability = ToolCapability.HTTP_CONTENT

    def _fallback_capability(self, todo: TodoItem, state: RunState) -> ToolCapability:
        if todo.context.get("forms") or todo.context.get("page_url"):
            return ToolCapability.HTTP_FORM_PROBE
        if todo.context.get("paths"):
            return ToolCapability.HTTP_PROBE_PATHS
        return ToolCapability.HTTP_CONTENT


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
    fallback_capability = ToolCapability.VULN_SCAN


class FlagWorker(PersonaWorker):
    """Persona worker for final flag hunting and validation."""

    name = "flag-worker"
    supported_todo_kinds = ("todo",)
    routing_summary = "Harvests and validates concrete flag candidates."
    allowed_capabilities = (
        ToolCapability.FLAG_HARVEST,
        ToolCapability.SCRIPT_EXECUTE,
    )
    fallback_capability = ToolCapability.FLAG_HARVEST

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
        candidates = _strings(task.context.get("candidate_flag"))
        if not candidates:
            candidates = [candidate.value for candidate in state.flag_candidates.values()]
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


def _standard_factory(worker_cls: type[PersonaWorker]):
    def factory(context: WorkerBuildContext) -> PersonaWorker:
        return worker_cls(
            llm_client=context.llm_client,
            execution_plane=context.execution_plane,
        )

    return factory


def _flag_factory(context: WorkerBuildContext) -> FlagWorker:
    return FlagWorker(
        llm_client=context.llm_client,
        execution_plane=context.execution_plane,
        expected_flag=context.expected_flag,
    )


PERSONA_WORKERS: tuple[type[PersonaWorker], ...] = (
    ReconWorker,
    ArtifactWorker,
    WebWorker,
    ExploitWorker,
    FlagWorker,
)

WORKER_SPECS: tuple[WorkerSpec, ...] = (
    WorkerSpec("ReconWorker", "persona", _standard_factory(ReconWorker), ReconWorker.routing_summary),
    WorkerSpec("ArtifactWorker", "persona", _standard_factory(ArtifactWorker), ArtifactWorker.routing_summary),
    WorkerSpec("WebWorker", "persona", _standard_factory(WebWorker), WebWorker.routing_summary),
    WorkerSpec("ExploitWorker", "persona", _standard_factory(ExploitWorker), ExploitWorker.routing_summary),
    WorkerSpec("FlagWorker", "persona", _flag_factory, FlagWorker.routing_summary),
)
