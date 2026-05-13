"""Parsers for raw tool output."""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from killchain_docker.state import Asset, Credential, Finding, NetworkEdge
from killchain_docker.tools.core import (
    ParsedToolOutput,
    ToolExecutionError,
    ToolExecutionRequest,
    ToolExecutionResult,
)


def jsonl_signal_parser(request: ToolExecutionRequest, result: ToolExecutionResult) -> ParsedToolOutput:
    """Parse JSONL signal records from stdout or plain response text."""

    del request
    source = result.stdout or result.response_text or ""
    summary = f"Executed {result.tool_name}."
    notes: list[str] = []

    if result.exit_code is not None and result.exit_code != 0:
        notes.append(f"Tool exited with code {result.exit_code}; output may be partial.")
    if result.status_code is not None and result.status_code >= 400:
        notes.append(f"HTTP status {result.status_code}; response may indicate failure.")
    if not source.strip():
        if (result.exit_code or 0) != 0:
            notes.append(
                f"No output produced (exit {result.exit_code}); stderr: {result.stderr[:500] if result.stderr else 'none'}"
            )
        else:
            notes.append("Tool produced no output; verify tool configuration.")

    output_context: dict[str, Any] = {}
    asset_updates: list[Asset] = []
    finding_updates: list[Finding] = []
    credential_updates: list[Credential] = []
    network_updates: list[NetworkEdge] = []

    for raw_line in source.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            notes.append(f"unparsed line: {line}")
            continue

        if not isinstance(payload, dict):
            notes.append(f"ignored non-object payload from {result.tool_name}")
            continue

        item_type = payload.get("type")
        if item_type == "summary":
            summary = str(payload.get("text") or payload.get("summary") or summary)
            continue
        if item_type == "note":
            if "text" in payload:
                notes.append(str(payload["text"]))
            continue
        if item_type == "output_context":
            output_context.update({key: value for key, value in payload.items() if key != "type"})
            continue

        data = {key: value for key, value in payload.items() if key != "type"}
        try:
            if item_type == "asset":
                asset_updates.append(Asset.model_validate(data))
            elif item_type == "finding":
                finding_updates.append(Finding.model_validate(data))
            elif item_type == "credential":
                credential_updates.append(Credential.model_validate(data))
            elif item_type == "network_edge":
                network_updates.append(NetworkEdge.model_validate(data))
            else:
                notes.append(f"ignored signal type: {item_type}")
        except ValidationError as exc:
            notes.append(f"invalid {item_type} payload: {exc}")

    return ParsedToolOutput(
        summary=summary,
        output_context=output_context,
        notes=notes,
        asset_updates=asset_updates,
        finding_updates=finding_updates,
        credential_updates=credential_updates,
        network_updates=network_updates,
    )


def json_payload_parser(request: ToolExecutionRequest, result: ToolExecutionResult) -> ParsedToolOutput:
    """Parse a single JSON object from a REST response."""

    del request
    notes: list[str] = []
    if result.status_code is not None and result.status_code >= 400:
        notes.append(f"HTTP status {result.status_code}; response may indicate failure.")
    payload = result.response_json
    if payload is None and result.response_text:
        try:
            decoded = json.loads(result.response_text)
        except json.JSONDecodeError as exc:
            raise ToolExecutionError(f"Response is not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise ToolExecutionError("Response JSON must be an object.")
        payload = decoded

    if payload is None:
        raise ToolExecutionError("No JSON payload available for json_payload parser.")

    try:
        assets = [Asset.model_validate(item) for item in payload.get("assets", [])]
        findings = [Finding.model_validate(item) for item in payload.get("findings", [])]
        credentials = [Credential.model_validate(item) for item in payload.get("credentials", [])]
        edges = [NetworkEdge.model_validate(item) for item in payload.get("network_edges", [])]
    except ValidationError as exc:
        raise ToolExecutionError(f"Invalid parsed REST payload: {exc}") from exc

    summary = str(payload.get("summary") or f"Executed {result.tool_name}.")
    notes.extend(str(item) for item in payload.get("notes", []))
    output_context = payload.get("output_context", {})
    if not isinstance(output_context, dict):
        raise ToolExecutionError("output_context must be a JSON object.")

    return ParsedToolOutput(
        summary=summary,
        output_context=output_context,
        notes=notes,
        asset_updates=assets,
        finding_updates=findings,
        credential_updates=credentials,
        network_updates=edges,
    )
