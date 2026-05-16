"""Core execution-plane types and safe transport plugins."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Protocol
from urllib import error, parse, request
from uuid import uuid4

from pydantic import BaseModel, Field

from killchain_docker.state import (
    Asset,
    Artifact,
    Credential,
    Endpoint,
    EvidenceRecord,
    ExploitAttempt,
    Finding,
    FlagCandidate,
    Hypothesis,
    NetworkEdge,
    Route,
    Session,
    StateDelta,
    Vulnerability,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _request_id() -> str:
    return f"request-{uuid4().hex[:10]}"


def _truncate(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"


def _strings(value: Any) -> list[str]:
    if value in (None, "", [], {}, ()):
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, dict):
        return []
    result: list[str] = []
    try:
        iterator = iter(value)
    except TypeError:
        text = str(value).strip()
        return [text] if text else []
    for item in iterator:
        text = str(item).strip()
        if text and text not in result:
            result.append(text)
    return result


def _first_string(value: Any) -> str | None:
    values = _strings(value)
    return values[0] if values else None


class ToolExecutionError(RuntimeError):
    """Raised when a plugin cannot safely execute a request."""


class ExecutionMode(StrEnum):
    SIMULATED = "simulated"
    LOCAL_COMMAND = "local_command"
    LOOPBACK_REST = "loopback_rest"


class ToolExecutionRequest(BaseModel):
    """Standardized request routed through the execution plane."""

    request_id: str = Field(default_factory=_request_id)
    capability: str | None = None
    tool_name: str
    parser_name: str = "jsonl_signals"
    arguments: list[str] = Field(default_factory=list)
    endpoint: str | None = None
    method: str = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    timeout_s: int = Field(default=60, ge=1)
    max_retries: int = Field(default=1, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResult(BaseModel):
    """Structured result returned by a plugin execution."""

    tool_name: str
    mode: ExecutionMode
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    status_code: int | None = None
    response_text: str | None = None
    response_json: dict[str, Any] | None = None
    executed_at: datetime = Field(default_factory=utc_now)


class ParsedToolOutput(BaseModel):
    """Transport-level JSON/JSONL decode result for a plugin output builder."""

    summary: str
    output_context: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    records: list[dict[str, Any]] = Field(default_factory=list)


class ToolOutputStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


class ToolOutput(BaseModel):
    """Unified output contract produced by one concrete plugin."""

    status: ToolOutputStatus = ToolOutputStatus.SUCCESS
    summary: str = ""
    output_text: str = ""
    notes: list[str] = Field(default_factory=list)
    raw_log: str = ""
    output_context: dict[str, Any] = Field(default_factory=dict)

    assets: list[Asset] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    routes: list[Route] = Field(default_factory=list)
    flag_candidates: list[FlagCandidate] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    exploit_attempts: list[ExploitAttempt] = Field(default_factory=list)
    sessions: list[Session] = Field(default_factory=list)
    credentials: list[Credential] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    network_edges: list[NetworkEdge] = Field(default_factory=list)

    def to_state_delta(self) -> StateDelta:
        """Convert state-delta fields into the state merge model."""
        return StateDelta(
            artifacts=self.artifacts,
            endpoints=self.endpoints,
            routes=self.routes,
            flag_candidates=self.flag_candidates,
            hypotheses=self.hypotheses,
            vulnerabilities=self.vulnerabilities,
            exploit_attempts=self.exploit_attempts,
            sessions=self.sessions,
        )


class ToolExecutionBundle(BaseModel):
    """Execution result plus parsed deltas and generated evidence."""

    request: ToolExecutionRequest
    result: ToolExecutionResult
    parsed: ParsedToolOutput
    tool_output: ToolOutput
    evidence: EvidenceRecord
    state_delta: StateDelta = Field(default_factory=StateDelta)


class ToolPlugin(Protocol):
    """Execution plugin protocol."""

    name: str
    mode: ExecutionMode

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        """Run one request and return raw structured output."""


ParserFn = Callable[[ToolExecutionRequest, ToolExecutionResult], ParsedToolOutput]
CommandBuilder = Callable[[ToolExecutionRequest], list[str]]
RestRequestBuilder = Callable[[ToolExecutionRequest], tuple[str, str, dict[str, str], dict[str, Any] | None]]
RestTransport = Callable[[str, str, dict[str, str], bytes | None, int], tuple[int, str]]


class AllowlistedCommandPlugin:
    """Runs a pre-defined local command without shell interpolation."""

    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(
        self,
        *,
        name: str,
        executable: str,
        build_arguments: CommandBuilder,
        argv_prefix: list[str] | None = None,
    ) -> None:
        self.name = name
        self.executable = executable
        self.build_arguments = build_arguments
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        argv = [*self.argv_prefix, self.executable, *self.build_arguments(request)]
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=request.timeout_s,
                check=False,
            )
        except OSError as exc:
            raise ToolExecutionError(f"Failed to execute {self.name}: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolExecutionError(f"{self.name} timed out after {request.timeout_s}s") from exc

        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


def _default_rest_transport(
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout_s: int,
) -> tuple[int, str]:
    http_request = request.Request(url, data=body, headers=headers, method=method)
    try:
        with request.urlopen(http_request, timeout=timeout_s) as response:
            payload = response.read().decode("utf-8")
            return response.status, payload
    except error.URLError as exc:
        raise ToolExecutionError(f"Loopback REST request failed: {exc}") from exc


class LoopbackRestPlugin:
    """Invokes an allowlisted local REST/RPC endpoint on the loopback interface only."""

    mode = ExecutionMode.LOOPBACK_REST

    def __init__(
        self,
        *,
        name: str,
        build_request: RestRequestBuilder,
        transport: RestTransport | None = None,
    ) -> None:
        self.name = name
        self.build_request = build_request
        self.transport = transport or _default_rest_transport

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        method, url, headers, payload = self.build_request(request)
        self._validate_loopback_url(url)
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json", **headers}
        status_code, response_text = self.transport(url, method, headers, body, request.timeout_s)

        response_json: dict[str, Any] | None = None
        if response_text:
            try:
                parsed = json.loads(response_text)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict):
                response_json = parsed

        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            status_code=status_code,
            response_text=response_text,
            response_json=response_json,
        )

    def _validate_loopback_url(self, url: str) -> None:
        parsed = parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ToolExecutionError(f"Loopback REST plugin requires http/https URL, got {parsed.scheme!r}")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ToolExecutionError("Loopback REST plugin only allows localhost targets.")


class ExecutionPlane:
    """Plugin registry plus parser registry for safe tool execution."""

    def __init__(self) -> None:
        self.plugins: dict[str, ToolPlugin] = {}
        self.parsers: dict[str, ParserFn] = {}
        # Per-plugin builders own structured output and typed signal emission.
        self._tool_output_builders: dict[str, Any] = {}

    def register_plugin(self, plugin: ToolPlugin) -> None:
        self.plugins[plugin.name] = plugin

    def register_tool_output_builder(self, tool_name: str, builder: Any) -> None:
        """Register the build_tool_output function for a specific plugin."""
        self._tool_output_builders[tool_name] = builder

    def register_parser(self, name: str, parser: ParserFn) -> None:
        self.parsers[name] = parser

    def execute(self, task_id: str, request: ToolExecutionRequest) -> ToolExecutionBundle:
        plugin = self.plugins.get(request.tool_name)
        if plugin is None:
            raise ToolExecutionError(f"Unknown tool plugin: {request.tool_name!r}")

        parser = self.parsers.get(request.parser_name)
        if parser is None:
            raise ToolExecutionError(f"Unknown parser: {request.parser_name!r}")

        last_exc: ToolExecutionError | None = None
        for attempt in range(1, request.max_retries + 2):
            try:
                result = plugin.execute(request)
                break
            except ToolExecutionError as exc:
                last_exc = exc
                if attempt <= request.max_retries:
                    continue
                raise ToolExecutionError(
                    f"{request.tool_name} failed after {attempt} attempt(s): {exc}"
                ) from exc

        raw_parsed = parser(request, result)
        custom_builder = self._tool_output_builders.get(request.tool_name)
        if custom_builder is None:
            raise ToolExecutionError(
                f"Tool plugin {request.tool_name!r} has no build_tool_output registered."
            )

        candidate_output = custom_builder(request, result, raw_parsed)
        tool_output = (
            candidate_output
            if isinstance(candidate_output, ToolOutput)
            else ToolOutput.model_validate(candidate_output)
        )
        parsed = ParsedToolOutput(
            summary=tool_output.summary,
            output_context=tool_output.output_context,
            notes=tool_output.notes,
            records=raw_parsed.records,
        )
        state_delta = tool_output.to_state_delta()
        evidence = self._build_evidence(task_id, request, result, tool_output)
        return ToolExecutionBundle(
            request=request,
            result=result,
            parsed=parsed,
            tool_output=tool_output,
            evidence=evidence,
            state_delta=state_delta,
        )

    def _build_evidence(
        self,
        task_id: str,
        request: ToolExecutionRequest,
        result: ToolExecutionResult,
        tool_output: ToolOutput,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            task_id=task_id,
            capability=request.capability,
            tool_name=request.tool_name,
            mode=result.mode.value,
            summary=tool_output.summary,
            parser_name=request.parser_name,
            request=request.model_dump(mode="json"),
            result={
                "exit_code": result.exit_code,
                "status_code": result.status_code,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
                "response_text": _truncate(result.response_text or ""),
                "response_json": result.response_json or {},
            },
            extracted={
                "notes": tool_output.notes,
                "output_context": tool_output.output_context,
                "assets": [asset.asset_id for asset in tool_output.assets],
                "artifacts": [artifact.path for artifact in tool_output.artifacts],
                "endpoints": [endpoint.url or endpoint.hostname for endpoint in tool_output.endpoints],
                "routes": [route.url for route in tool_output.routes],
                "flag_candidates": [candidate.value for candidate in tool_output.flag_candidates],
                "findings": [finding.finding_id for finding in tool_output.findings],
                "credentials": [credential.credential_id for credential in tool_output.credentials],
                "network_edges": [
                    f"{edge.source}->{edge.target}:{edge.relationship}"
                    for edge in tool_output.network_edges
                ],
            },
        )
