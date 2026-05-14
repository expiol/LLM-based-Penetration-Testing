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
    NetworkEdge,
    Route,
    Session,
    StateDelta,
    Vulnerability,
)
from killchain_docker.state.constants import validatable_flag_candidate


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _request_id() -> str:
    return f"request-{uuid4().hex[:10]}"


def _truncate(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return f"{value[:limit]}...[truncated]"


def _string_list(value: Any) -> list[str]:
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


def _flag_candidate_values(ctx: dict[str, Any], *, flag_format: object = None) -> list[str]:
    from killchain_docker.orchestrator.policy import CandidatePolicy

    values: list[str] = []
    for key in ("flag_candidates", "potential_flags", "grounded_flag_candidates"):
        for value in _string_list(ctx.get(key)):
            if value in values or not validatable_flag_candidate(value):
                continue
            if not CandidatePolicy.decision(value, flag_format=flag_format).accepted:
                continue
            values.append(value)
    return values


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _first_string(value: Any) -> str | None:
    values = _string_list(value)
    return values[0] if values else None


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _looks_like_url(value: str) -> bool:
    parsed = parse.urlparse(value)
    return parsed.scheme in {"http", "https", "tcp"} and bool(parsed.netloc)


def _normalize_route_url(
    value: Any,
    ctx: dict[str, Any],
    request: ToolExecutionRequest,
) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if _looks_like_url(text):
        return text
    if not text.startswith("/"):
        return None
    base = (
        _first_string(ctx.get("base_url"))
        or _first_string(ctx.get("observed_base_url"))
        or _first_string(request.metadata.get("base_url"))
    )
    if not base or not _looks_like_url(base):
        return text
    return parse.urljoin(base.rstrip("/") + "/", text.lstrip("/"))


def _iter_binary_run_files(binary_runs: Any) -> list[dict[str, Any]]:
    if not isinstance(binary_runs, dict):
        return []
    result: list[dict[str, Any]] = []
    for binary_name, body in binary_runs.items():
        if not isinstance(body, dict):
            continue
        for invocation in body.get("invocations") or []:
            if not isinstance(invocation, dict):
                continue
            for key, change_type in (("new_files", "created"), ("changed_files", "modified")):
                for item in invocation.get(key) or []:
                    if isinstance(item, dict):
                        result.append({
                            **item,
                            "binary": binary_name,
                            "invocation": invocation.get("label"),
                            "change_type": change_type,
                        })
    return result


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
        state_delta = self._build_state_delta(request, parsed)
        evidence = self._build_evidence(task_id, request, result, parsed)
        return ToolExecutionBundle(
            request=request,
            result=result,
            parsed=parsed,
            evidence=evidence,
            state_delta=state_delta,
        )

    def _build_state_delta(
        self,
        request: ToolExecutionRequest,
        parsed: ParsedToolOutput,
    ) -> StateDelta:
        """Lift common plugin output fields into typed state facts."""

        ctx = parsed.output_context or {}
        tool_name = request.tool_name
        source_name = request.capability or tool_name
        asset_ref = _first_string(request.metadata.get("asset_id"))
        evidence_refs: list[str] = []

        artifacts: list[Artifact] = []
        for key, kind in (
            ("challenge_files", "challenge_file"),
            ("source_files", "source"),
            ("inspected_sources", "source"),
            ("inspected_files", "file"),
            ("inspected_binaries", "binary"),
            ("binary_files", "binary"),
            ("inspected_archives", "archive"),
            ("archive_files", "archive"),
            ("inspected_pcaps", "pcap"),
            ("pcap_files", "pcap"),
            ("inspected_databases", "database"),
            ("database_files", "database"),
            ("inspected_repos", "repository"),
            ("repo_paths", "repository"),
        ):
            for path in _string_list(ctx.get(key)):
                artifacts.append(
                    Artifact(
                        path=path,
                        kind=kind,
                        source=source_name,
                        metadata={"field": key},
                    )
                )
                evidence_refs.append(path)

        for item in _iter_binary_run_files(ctx.get("binary_runs")):
            path = str(item.get("name") or "").strip()
            if not path:
                continue
            artifacts.append(
                Artifact(
                    path=path,
                    kind=str(item.get("kind") or "generated_file"),
                    source=source_name,
                    size=_optional_int(item.get("size")),
                    preview=str(item.get("preview") or "")[:1000] or None,
                    metadata={
                        "binary": item.get("binary"),
                        "invocation": item.get("invocation"),
                        "change_type": item.get("change_type", "created"),
                    },
                )
            )

        endpoints: list[Endpoint] = []
        for url_key in ("observed_base_url", "base_url", "page_url", "target_url"):
            url = _first_string(ctx.get(url_key))
            if not url or not _looks_like_url(url):
                continue
            parsed_url = parse.urlparse(url)
            endpoints.append(
                Endpoint(
                    asset_ref=asset_ref,
                    url=url,
                    hostname=parsed_url.hostname,
                    port=parsed_url.port,
                    protocol=parsed_url.scheme or None,
                    status_code=_optional_int(ctx.get("http_status")),
                    title=_first_string(ctx.get("title")),
                    metadata={"field": url_key, "capability": source_name, "tool": tool_name},
                )
            )

        routes: list[Route] = []
        for url in _string_list(ctx.get("interesting_paths")):
            route_url = _normalize_route_url(url, ctx, request)
            if route_url:
                routes.append(
                    Route(
                        asset_ref=asset_ref,
                        url=route_url,
                        path=parse.urlparse(route_url).path or route_url,
                        source=source_name,
                    )
                )
        for item in _dict_list(ctx.get("path_results")):
            route_url = _normalize_route_url(item.get("url") or item.get("path"), ctx, request)
            if not route_url:
                continue
            routes.append(
                Route(
                    asset_ref=asset_ref,
                    url=route_url,
                    path=parse.urlparse(route_url).path or route_url,
                    status_code=_optional_int(item.get("status") or item.get("status_code")),
                    source=source_name,
                    metadata={
                        key: item[key]
                        for key in ("title", "content_type", "redirect")
                        if key in item
                    },
                )
            )

        flag_candidates = [
            FlagCandidate(
                value=value,
                source=source_name,
                confidence=0.65,
                evidence_refs=evidence_refs[:8],
            )
            for value in _flag_candidate_values(ctx, flag_format=request.metadata.get("flag_format"))
        ]

        vulnerabilities = [
            Vulnerability(
                title=issue[:160],
                asset_ref=asset_ref,
                description=issue,
                metadata={"source": source_name, "tool": tool_name},
            )
            for issue in _string_list(ctx.get("security_issues"))
        ]

        sessions = [
            Session(
                asset_ref=asset_ref,
                session_type="credential",
                secret_ref=credential_id,
                metadata={"source": source_name, "tool": tool_name},
            )
            for credential_id in _string_list(ctx.get("successful_credential_ids"))
        ]

        exploit_attempts: list[ExploitAttempt] = []
        capability = source_name
        if capability in {"script.execute", "exploit.probe", "credential.login"}:
            exploit_attempts.append(
                ExploitAttempt(
                    technique=capability,
                    success=bool(flag_candidates or sessions),
                    summary=parsed.summary,
                    flag_candidate_refs=[item.value for item in flag_candidates],
                    metadata={
                        "returncode": ctx.get("returncode"),
                        "result_quality": ctx.get("result_quality"),
                        "partial_reason": ctx.get("partial_reason"),
                        "failure_kind": ctx.get("failure_kind"),
                        "failure_detail": ctx.get("failure_detail"),
                        "near_miss_candidates": ctx.get("near_miss_candidates") or [],
                    },
                )
            )

        return StateDelta(
            artifacts=artifacts,
            endpoints=endpoints,
            routes=routes,
            flag_candidates=flag_candidates,
            vulnerabilities=vulnerabilities,
            exploit_attempts=exploit_attempts,
            sessions=sessions,
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
            capability=request.capability,
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
