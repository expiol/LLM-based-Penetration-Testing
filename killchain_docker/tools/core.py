"""Core execution-plane types and safe transport plugins."""

from __future__ import annotations

import json
import subprocess
from collections.abc import Callable
from datetime import datetime, timezone
from killchain_docker.compat import StrEnum
from typing import Any, Protocol
from urllib import error, parse, request
from uuid import uuid4

from pydantic import BaseModel, Field

from killchain_docker.state import (
    Asset,
    Credential,
    EvidenceRecord,
    Finding,
    NetworkEdge,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _request_id() -> str:
    return f"request-{uuid4().hex[:10]}"


def _truncate(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"


class ToolExecutionError(RuntimeError):
    """Raised when a plugin cannot safely execute a request."""


class ExecutionMode(StrEnum):
    SIMULATED = "simulated"
    LOCAL_COMMAND = "local_command"
    LOOPBACK_REST = "loopback_rest"


class ToolExecutionRequest(BaseModel):
    """Standardized request routed through the execution plane."""

    request_id: str = Field(default_factory=_request_id)
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
    """Structured state deltas extracted from raw tool output."""

    summary: str
    output_context: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    asset_updates: list[Asset] = Field(default_factory=list)
    finding_updates: list[Finding] = Field(default_factory=list)
    credential_updates: list[Credential] = Field(default_factory=list)
    network_updates: list[NetworkEdge] = Field(default_factory=list)


class ToolExecutionBundle(BaseModel):
    """Execution result plus parsed deltas and generated evidence."""

    request: ToolExecutionRequest
    result: ToolExecutionResult
    parsed: ParsedToolOutput
    evidence: EvidenceRecord


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

    def register_plugin(self, plugin: ToolPlugin) -> None:
        self.plugins[plugin.name] = plugin

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

        parsed = parser(request, result)
        evidence = self._build_evidence(task_id, request, result, parsed)
        return ToolExecutionBundle(
            request=request,
            result=result,
            parsed=parsed,
            evidence=evidence,
        )

    def _build_evidence(
        self,
        task_id: str,
        request: ToolExecutionRequest,
        result: ToolExecutionResult,
        parsed: ParsedToolOutput,
    ) -> EvidenceRecord:
        return EvidenceRecord(
            task_id=task_id,
            tool_name=request.tool_name,
            mode=result.mode.value,
            summary=parsed.summary,
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
                "notes": parsed.notes,
                "output_context": parsed.output_context,
                "assets": [asset.asset_id for asset in parsed.asset_updates],
                "findings": [finding.finding_id for finding in parsed.finding_updates],
                "credentials": [credential.credential_id for credential in parsed.credential_updates],
            },
        )
