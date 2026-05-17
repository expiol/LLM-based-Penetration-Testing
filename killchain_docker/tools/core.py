"""Core execution-plane types.

Data models, protocols, and the ExecutionPlane registry.
Concrete plugins live in ``tools.plugins``.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import datetime
from killchain_docker._compat import StrEnum
from typing import Any, Protocol
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
from killchain_docker.state.models import utc_now


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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


from killchain_docker.state.constants import FLAG_PATTERN, plausible_flag


def extract_flags_from_text(text: str) -> list[str]:
    """Scan text for flag-like tokens ``prefix{body}``.

    Uses the canonical FLAG_PATTERN from state.constants (single source of
    truth) and applies plausibility filtering to reject CSS/template noise.
    """
    raw = FLAG_PATTERN.findall(text)
    return list(dict.fromkeys(c for c in raw if plausible_flag(c)))


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class ToolExecutionError(RuntimeError):
    """Raised when a plugin cannot safely execute a request."""


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ExecutionMode(StrEnum):
    LOCAL_COMMAND = "local_command"
    SIMULATED = "simulated"


# ---------------------------------------------------------------------------
# Request / Result models
# ---------------------------------------------------------------------------

class ToolExecutionRequest(BaseModel):
    """Standardized request routed through the execution plane."""

    request_id: str = Field(default_factory=_request_id)
    capability: str | None = None
    tool_name: str
    arguments: list[str] = Field(default_factory=list)
    timeout_s: int = Field(default=120, ge=1)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ToolExecutionResult(BaseModel):
    """Raw result returned by a plugin."""

    tool_name: str
    mode: ExecutionMode = ExecutionMode.LOCAL_COMMAND
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    executed_at: datetime = Field(default_factory=utc_now)


class ToolOutputStatus(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"


class ParsedToolOutput(BaseModel):
    """Intermediate parse result fed into the output builder."""

    summary: str
    output_context: dict[str, Any] = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)
    records: list[dict[str, Any]] = Field(default_factory=list)


class ToolOutput(BaseModel):
    """Unified output contract produced by a plugin's output builder."""

    status: ToolOutputStatus = ToolOutputStatus.SUCCESS
    summary: str = ""
    output_text: str = ""
    notes: list[str] = Field(default_factory=list)
    raw_log: str = ""
    output_context: dict[str, Any] = Field(default_factory=dict)

    # Typed state signals
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


# ---------------------------------------------------------------------------
# Plugin protocol
# ---------------------------------------------------------------------------

class ToolPlugin(Protocol):
    name: str
    mode: ExecutionMode

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult: ...


ToolOutputBuilder = Callable[
    [ToolExecutionRequest, ToolExecutionResult, ParsedToolOutput],
    ToolOutput,
]


# ---------------------------------------------------------------------------
# ExecutionPlane — plugin registry + execution
# ---------------------------------------------------------------------------

class ExecutionPlane:
    """Registry of tool plugins.  Executes requests and builds evidence."""

    def __init__(self) -> None:
        self.plugins: dict[str, ToolPlugin] = {}
        self._output_builders: dict[str, ToolOutputBuilder] = {}

    def register(self, plugin: ToolPlugin, output_builder: ToolOutputBuilder) -> None:
        self.plugins[plugin.name] = plugin
        self._output_builders[plugin.name] = output_builder

    def execute(self, task_id: str, request: ToolExecutionRequest) -> ToolExecutionBundle:
        plugin = self.plugins.get(request.tool_name)
        if plugin is None:
            raise ToolExecutionError(f"Unknown tool: {request.tool_name!r}")

        builder = self._output_builders.get(request.tool_name)
        if builder is None:
            raise ToolExecutionError(f"No output builder for {request.tool_name!r}")

        result = plugin.execute(request)

        # Lightweight parse: extract summary + flag candidates from stdout
        parsed = _parse_raw_output(request, result)
        tool_output = builder(request, result, parsed)
        if not isinstance(tool_output, ToolOutput):
            tool_output = ToolOutput.model_validate(tool_output)

        state_delta = tool_output.to_state_delta()
        evidence = self._build_evidence(task_id, request, result, tool_output)

        return ToolExecutionBundle(
            request=request,
            result=result,
            parsed=ParsedToolOutput(
                summary=tool_output.summary,
                output_context=tool_output.output_context,
                notes=tool_output.notes,
            ),
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
            parser_name="raw",
            request=request.model_dump(mode="json"),
            result={
                "exit_code": result.exit_code,
                "stdout": _truncate(result.stdout),
                "stderr": _truncate(result.stderr),
            },
            extracted={
                "notes": tool_output.notes,
                "output_context": tool_output.output_context,
                "flag_candidates": [c.value for c in tool_output.flag_candidates],
            },
        )


def _parse_raw_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
) -> ParsedToolOutput:
    """Lightweight parse: build summary and extract flag candidates."""
    notes: list[str] = []
    if result.exit_code not in (None, 0):
        notes.append(f"exit code {result.exit_code}")
    if not result.stdout.strip() and not result.stderr.strip():
        notes.append("no output produced")

    stdout_preview = _truncate(result.stdout, 3000)
    stderr_preview = _truncate(result.stderr, 1500)
    flags = extract_flags_from_text(result.stdout)

    summary = f"{request.tool_name}: exit {result.exit_code}"
    if flags:
        summary += f", {len(flags)} flag candidate(s)"

    return ParsedToolOutput(
        summary=summary,
        output_context={
            "stdout": stdout_preview,
            "stderr": stderr_preview,
            "returncode": result.exit_code,
            "flag_candidates": flags,
        },
        notes=notes,
    )
