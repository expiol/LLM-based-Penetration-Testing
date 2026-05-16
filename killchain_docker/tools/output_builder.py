"""Helper library for plugin-specific build_tool_output functions.

These helpers do not run in the execution plane automatically. A concrete
plugin must call the pieces that match its own output records and context.
"""

from __future__ import annotations

from typing import Any
from urllib import parse

from pydantic import BaseModel, ValidationError

from killchain_docker.state import (
    Asset,
    Artifact,
    Credential,
    Endpoint,
    ExploitAttempt,
    Finding,
    FlagCandidate,
    NetworkEdge,
    Route,
    Session,
    Vulnerability,
)
from killchain_docker.state.constants import validatable_flag_candidate
from killchain_docker.tools.core import ToolOutput, ToolOutputStatus


# ---------------------------------------------------------------------------
# Internal utilities (ported from core.py)
# ---------------------------------------------------------------------------

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


def _optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _looks_like_url(value: str) -> bool:
    parsed = parse.urlparse(value)
    return parsed.scheme in {"http", "https", "tcp"} and bool(parsed.netloc)


def _normalize_route_url(value: Any, ctx: dict, request: Any) -> str | None:
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


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


# ---------------------------------------------------------------------------
# Public extraction helpers
# ---------------------------------------------------------------------------


def status_from_result(result: Any) -> ToolOutputStatus:
    if result.exit_code is not None and result.exit_code != 0:
        return ToolOutputStatus.FAILURE
    return ToolOutputStatus.SUCCESS


def base_output(request: Any, result: Any, parsed: Any) -> ToolOutput:
    """Build the common ToolOutput envelope from records emitted by a plugin."""
    notes = list(parsed.notes)
    assets = _typed_records(parsed, "asset", Asset, notes)
    findings = _typed_records(parsed, "finding", Finding, notes)
    credentials = _typed_records(parsed, "credential", Credential, notes)
    network_edges = _typed_records(parsed, "network_edge", NetworkEdge, notes)
    return ToolOutput(
        status=status_from_result(result),
        summary=parsed.summary,
        output_text=parsed.summary,
        notes=notes,
        raw_log=result.stdout[-4000:] if result.stdout else "",
        assets=assets,
        findings=findings,
        credentials=credentials,
        network_edges=network_edges,
        output_context=parsed.output_context or {},
    )


def _typed_records(parsed: Any, item_type: str, model: type[BaseModel], notes: list[str]) -> list[Any]:
    records = getattr(parsed, "records", []) or []
    typed: list[Any] = []
    for payload in records:
        if not isinstance(payload, dict) or payload.get("type") != item_type:
            continue
        data = {key: value for key, value in payload.items() if key != "type"}
        try:
            typed.append(model.model_validate(data))
        except ValidationError as exc:
            notes.append(f"invalid {item_type} payload from plugin: {exc}")
    return typed


def extract_flag_candidates(
    ctx: dict[str, Any],
    *,
    source: str = "",
    flag_format: Any = None,
    evidence_refs: list[str] | None = None,
) -> list[FlagCandidate]:
    from killchain_docker.orchestrator.policy import CandidatePolicy

    values: list[str] = []
    for key in ("flag_candidates", "potential_flags", "grounded_flag_candidates"):
        for value in _strings(ctx.get(key)):
            if value in values or not validatable_flag_candidate(value):
                continue
            if not CandidatePolicy.decision(value, flag_format=flag_format).accepted:
                continue
            values.append(value)
    return [
        FlagCandidate(
            value=v,
            source=source,
            confidence=0.65,
            evidence_refs=(evidence_refs or [])[:8],
        )
        for v in values
    ]


def extract_artifacts(
    ctx: dict[str, Any],
    *,
    source: str = "",
    keys: dict[str, str] | None = None,
) -> list[Artifact]:
    """Extract artifacts from output_context. keys maps ctx_key -> artifact kind."""
    if keys is None:
        keys = {
            "challenge_files": "challenge_file",
            "source_files": "source",
            "inspected_sources": "source",
            "inspected_files": "file",
            "inspected_binaries": "binary",
            "binary_files": "binary",
            "inspected_archives": "archive",
            "archive_files": "archive",
            "inspected_pcaps": "pcap",
            "pcap_files": "pcap",
            "inspected_databases": "database",
            "database_files": "database",
            "inspected_repos": "repository",
            "repo_paths": "repository",
        }
    artifacts: list[Artifact] = []
    for ctx_key, kind in keys.items():
        for path in _strings(ctx.get(ctx_key)):
            artifacts.append(Artifact(path=path, kind=kind, source=source, metadata={"field": ctx_key}))
    return artifacts


def extract_endpoints(
    ctx: dict[str, Any],
    request: Any,
    *,
    source: str = "",
    asset_ref: str | None = None,
) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    for url_key in ("observed_base_url", "base_url", "page_url", "target_url"):
        url = _first_string(ctx.get(url_key))
        if not url or not _looks_like_url(url):
            continue
        parsed_url = parse.urlparse(url)
        endpoints.append(Endpoint(
            asset_ref=asset_ref,
            url=url,
            hostname=parsed_url.hostname,
            port=parsed_url.port,
            protocol=parsed_url.scheme or None,
            status_code=_optional_int(ctx.get("http_status")),
            title=_first_string(ctx.get("title")),
            metadata={"field": url_key, "capability": source, "tool": request.tool_name},
        ))
    return endpoints


def extract_routes(
    ctx: dict[str, Any],
    request: Any,
    *,
    source: str = "",
    asset_ref: str | None = None,
) -> list[Route]:
    routes: list[Route] = []
    for url in _strings(ctx.get("interesting_paths")):
        route_url = _normalize_route_url(url, ctx, request)
        if route_url:
            routes.append(Route(
                asset_ref=asset_ref,
                url=route_url,
                path=parse.urlparse(route_url).path or route_url,
                source=source,
            ))
    for item in _dict_list(ctx.get("path_results")):
        route_url = _normalize_route_url(item.get("url") or item.get("path"), ctx, request)
        if not route_url:
            continue
        routes.append(Route(
            asset_ref=asset_ref,
            url=route_url,
            path=parse.urlparse(route_url).path or route_url,
            status_code=_optional_int(item.get("status") or item.get("status_code")),
            source=source,
            metadata={k: item[k] for k in ("title", "content_type", "redirect") if k in item},
        ))
    return routes


def extract_vulnerabilities(
    ctx: dict[str, Any],
    *,
    source: str = "",
    tool_name: str = "",
    asset_ref: str | None = None,
) -> list[Vulnerability]:
    return [
        Vulnerability(
            title=issue[:160],
            asset_ref=asset_ref,
            description=issue,
            metadata={"source": source, "tool": tool_name},
        )
        for issue in _strings(ctx.get("security_issues"))
    ]


def extract_sessions(
    ctx: dict[str, Any],
    *,
    source: str = "",
    tool_name: str = "",
    asset_ref: str | None = None,
) -> list[Session]:
    return [
        Session(
            asset_ref=asset_ref,
            session_type="credential",
            secret_ref=cid,
            metadata={"source": source, "tool": tool_name},
        )
        for cid in _strings(ctx.get("successful_credential_ids"))
    ]


def extract_exploit_attempts(
    parsed: Any,
    *,
    source: str = "",
    flag_candidates: list[FlagCandidate] | None = None,
    sessions: list[Session] | None = None,
) -> list[ExploitAttempt]:
    ctx = parsed.output_context or {}
    return [ExploitAttempt(
        technique=source,
        success=bool(flag_candidates or sessions),
        summary=parsed.summary,
        flag_candidate_refs=[fc.value for fc in (flag_candidates or [])],
        metadata={
            "returncode": ctx.get("returncode"),
            "result_quality": ctx.get("result_quality"),
            "partial_reason": ctx.get("partial_reason"),
            "failure_kind": ctx.get("failure_kind"),
            "failure_detail": ctx.get("failure_detail"),
            "near_miss_candidates": ctx.get("near_miss_candidates") or [],
        },
    )]


def extract_binary_run_artifacts(ctx: dict[str, Any], *, source: str = "") -> list[Artifact]:
    binary_runs = ctx.get("binary_runs")
    if not isinstance(binary_runs, dict):
        return []
    artifacts: list[Artifact] = []
    for binary_name, body in binary_runs.items():
        if not isinstance(body, dict):
            continue
        for invocation in body.get("invocations") or []:
            if not isinstance(invocation, dict):
                continue
            for key, change_type in (("new_files", "created"), ("changed_files", "modified")):
                for item in invocation.get(key) or []:
                    if not isinstance(item, dict):
                        continue
                    path = str(item.get("name") or "").strip()
                    if not path:
                        continue
                    artifacts.append(Artifact(
                        path=path,
                        kind=str(item.get("kind") or "generated_file"),
                        source=source,
                        size=_optional_int(item.get("size")),
                        preview=str(item.get("preview") or "")[:1000] or None,
                        metadata={
                            "binary": binary_name,
                            "invocation": invocation.get("label"),
                            "change_type": change_type,
                        },
                    ))
    return artifacts
