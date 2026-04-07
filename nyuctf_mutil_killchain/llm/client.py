"""Minimal structured-output LLM clients."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeVar
from urllib import error, request

from pydantic import BaseModel, ConfigDict, Field

ModelT = TypeVar("ModelT", bound=BaseModel)
Transport = Callable[[str, dict[str, str], bytes, int], dict[str, Any]]

SUMMARY_FALLBACK_KEYS = (
    "summary",
    "overview",
    "rationale",
    "analysis",
    "notes",
    "note",
    "description",
    "message",
    "explanation",
)

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "summary": SUMMARY_FALLBACK_KEYS,
    "risk_hypotheses": ("risk_hypotheses", "riskHypotheses", "risks", "hypotheses"),
    "manual_checks": ("manual_checks", "manualChecks", "recommended_checks", "next_steps", "checks"),
    "recommended_checks": ("recommended_checks", "manual_checks", "manualChecks", "checks", "next_steps"),
    "interesting_paths": (
        "interesting_paths",
        "interestingPaths",
        "interesting_routes",
        "interestingRoutes",
        "paths",
        "routes",
        "http_paths",
        "httpPaths",
    ),
    "interesting_endpoints": (
        "interesting_endpoints",
        "interestingEndpoints",
        "interesting_routes",
        "interestingRoutes",
        "interesting_links",
        "interestingLinks",
        "links",
        "routes",
    ),
    "grounded_flag_candidates": (
        "grounded_flag_candidates",
        "groundedFlagCandidates",
        "flag_candidates",
        "flagCandidates",
        "flag_evidence",
        "flagEvidence",
        "potential_flags",
        "potentialFlags",
    ),
    "potential_flags": (
        "potential_flags",
        "potentialFlags",
        "flag_candidates",
        "flagCandidates",
        "flag_evidence",
        "flagEvidence",
    ),
    "attack_surface": ("attack_surface", "attackSurface", "surface", "attack_vectors"),
    "prioritized_credential_ids": (
        "prioritized_credential_ids",
        "prioritizedCredentialIds",
        "credential_ids",
        "credentialIds",
    ),
    "http_paths": (
        "http_paths",
        "httpPaths",
        "interesting_paths",
        "interestingPaths",
        "interesting_routes",
        "interestingRoutes",
        "paths",
        "routes",
    ),
    "tcp_inputs": ("tcp_inputs", "tcpInputs", "inputs", "prompts"),
    "focus_ports": ("focus_ports", "focusPorts", "ports"),
    "query_variants": (
        "query_variants",
        "queryVariants",
        "queries",
        "query_strings",
        "queryStrings",
        "url_queries",
        "urlQueries",
        "payload_queries",
    ),
    "text_payloads": (
        "text_payloads",
        "textPayloads",
        "payloads",
        "text_inputs",
        "textInputs",
        "input_values",
        "inputValues",
        "form_values",
        "formValues",
    ),
    "filename_variants": (
        "filename_variants",
        "filenameVariants",
        "filenames",
        "file_names",
        "fileNames",
        "upload_filenames",
        "uploadFilenames",
    ),
    "should_schedule_exploit_hypothesis": (
        "should_schedule_exploit_hypothesis",
        "shouldScheduleExploitHypothesis",
        "promote_exploit_reasoning",
        "promoteExploitReasoning",
        "should_promote_exploit_reasoning",
    ),
}


def _canonical_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def _iter_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, dict):
        for key in ("path", "url", "route", "endpoint", "text", "summary", "description", "reason", "title"):
            nested = value.get(key)
            if isinstance(nested, str) and nested.strip():
                return [nested.strip()]
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items: list[str] = []
        for item in value:
            for text in _iter_strings(item):
                if text and text not in items:
                    items.append(text)
        return items
    return []


def _iter_ints(value: Any) -> list[int]:
    if value is None:
        return []
    if isinstance(value, dict):
        for key in ("port", "value"):
            if key in value:
                return _iter_ints(value.get(key))
        return []
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items: list[int] = []
        for item in value:
            for number in _iter_ints(item):
                if number not in items:
                    items.append(number)
        return items
    try:
        number = int(value)
    except (TypeError, ValueError):
        return []
    return [number]


def _merge_string_lists(*groups: Sequence[str] | None) -> list[str]:
    merged: list[str] = []
    for group in groups:
        if not group:
            continue
        for item in group:
            text = str(item).strip()
            if not text or text in merged:
                continue
            merged.append(text)
    return merged


def _field_aliases(field_name: str) -> tuple[str, ...]:
    aliases = FIELD_ALIASES.get(field_name)
    if aliases is not None:
        return aliases
    return (field_name,)


def _lookup_value(payload: dict[str, Any], field_name: str) -> Any:
    if field_name in payload:
        return payload[field_name]

    wanted = {_canonical_key(alias) for alias in _field_aliases(field_name)}
    for key, value in payload.items():
        if _canonical_key(key) in wanted:
            return value
    return None


def _synthesized_summary(payload: dict[str, Any]) -> str:
    for key in SUMMARY_FALLBACK_KEYS:
        value = _lookup_value(payload, key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    for key in (
        "interesting_paths",
        "interesting_routes",
        "interesting_endpoints",
        "interesting_links",
        "http_paths",
        "flag_candidates",
        "grounded_flag_candidates",
        "potential_flags",
        "manual_checks",
        "recommended_checks",
        "hypotheses",
    ):
        items = _iter_strings(_lookup_value(payload, key))
        if items:
            preview = ", ".join(items[:3])
            return f"Model provided grounded guidance for: {preview}."
    return "Model returned structured guidance."


def _extract_form_probe_lists(payload: dict[str, Any]) -> dict[str, list[str]]:
    """Coerce common form-planning wrappers into FormProbeGuidance-compatible lists."""

    wanted = {
        _canonical_key("form_probe_variants"),
        _canonical_key("formProbeVariants"),
        _canonical_key("variants"),
        _canonical_key("test_cases"),
        _canonical_key("testCases"),
    }
    variants_value = None
    for key, value in payload.items():
        if _canonical_key(key) in wanted:
            variants_value = value
            break
    if not isinstance(variants_value, Sequence) or isinstance(variants_value, (str, bytes, bytearray)):
        return {}

    query_variants: list[str] = []
    text_payloads: list[str] = []
    filename_variants: list[str] = []
    manual_checks: list[str] = []

    for variant in variants_value:
        if not isinstance(variant, dict):
            continue
        query_variants = _merge_string_lists(
            query_variants,
            _iter_strings(
                variant.get("query_variant")
                or variant.get("query")
                or variant.get("query_string")
                or variant.get("url_query")
            ),
        )
        text_payloads = _merge_string_lists(
            text_payloads,
            _iter_strings(
                variant.get("text_payload")
                or variant.get("payload")
                or variant.get("content")
                or variant.get("body")
                or variant.get("value")
            ),
        )
        filename_variants = _merge_string_lists(
            filename_variants,
            _iter_strings(
                variant.get("filename")
                or variant.get("file_name")
                or variant.get("upload_filename")
            ),
        )
        manual_checks = _merge_string_lists(
            manual_checks,
            _iter_strings(
                variant.get("test_case")
                or variant.get("name")
                or variant.get("description")
                or variant.get("reason")
            ),
        )

        inputs = variant.get("inputs")
        if isinstance(inputs, dict):
            for value in inputs.values():
                if isinstance(value, dict):
                    query_variants = _merge_string_lists(
                        query_variants,
                        _iter_strings(
                            value.get("query_variant")
                            or value.get("query")
                            or value.get("query_string")
                            or value.get("url_query")
                        ),
                    )
                    text_payloads = _merge_string_lists(
                        text_payloads,
                        _iter_strings(
                            value.get("text")
                            or value.get("content")
                            or value.get("body")
                            or value.get("value")
                        ),
                    )
                    filename_variants = _merge_string_lists(
                        filename_variants,
                        _iter_strings(
                            value.get("filename")
                            or value.get("file_name")
                            or value.get("name")
                        ),
                    )
                else:
                    text_payloads = _merge_string_lists(text_payloads, _iter_strings(value))

    extracted: dict[str, list[str]] = {}
    if query_variants:
        extracted["query_variants"] = query_variants
    if text_payloads:
        extracted["text_payloads"] = text_payloads
    if filename_variants:
        extracted["filename_variants"] = filename_variants
    if manual_checks:
        extracted["manual_checks"] = manual_checks
    return extracted


def _massage_payload_for_schema(payload: Any, schema: type[ModelT]) -> Any:
    if not isinstance(payload, dict):
        return payload

    field_names = set(schema.model_fields)
    nested_candidates = [payload]
    for value in payload.values():
        if isinstance(value, dict):
            nested_candidates.append(value)

    def candidate_score(candidate: dict[str, Any]) -> int:
        score = 0
        for field_name in field_names:
            if _lookup_value(candidate, field_name) is not None:
                score += 2
        if _lookup_value(candidate, "summary") is not None:
            score += 1
        return score

    selected = max(nested_candidates, key=candidate_score)
    normalized: dict[str, Any] = {}
    for field_name in schema.model_fields:
        value = _lookup_value(selected, field_name)
        if value is None:
            continue
        if field_name == "summary":
            if isinstance(value, str) and value.strip():
                normalized[field_name] = value.strip()
            continue
        if field_name in {
            "risk_hypotheses",
            "manual_checks",
            "recommended_checks",
            "interesting_paths",
            "interesting_endpoints",
            "grounded_flag_candidates",
            "potential_flags",
            "attack_surface",
            "prioritized_credential_ids",
            "http_paths",
            "tcp_inputs",
            "hypotheses",
            "focus_asset_ids",
            "login_paths",
            "privileged_paths",
        }:
            normalized[field_name] = _iter_strings(value)
            continue
        if field_name == "focus_ports":
            normalized[field_name] = _iter_ints(value)
            continue
        normalized[field_name] = value

    if {"query_variants", "text_payloads", "filename_variants"} & field_names:
        for field_name, values in _extract_form_probe_lists(selected).items():
            if field_name not in field_names:
                continue
            normalized[field_name] = _merge_string_lists(normalized.get(field_name), values)

    if "summary" in field_names and not normalized.get("summary"):
        normalized["summary"] = _synthesized_summary(selected)
    return normalized or selected


class LLMClientError(RuntimeError):
    """Raised when an LLM call or response cannot be used safely."""


class LLMClient(Protocol):
    """Protocol for workers and planners that require structured JSON output."""

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        """Return a response validated against the requested Pydantic schema."""


class LLMSettings(BaseModel):
    """Environment-backed configuration for LLM access."""

    model_config = ConfigDict(extra="ignore")

    mode: str = "disabled"
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    timeout_s: int = Field(default=30, ge=1)

    @classmethod
    def from_env(cls) -> "LLMSettings":
        return cls(
            mode=os.getenv("AUTOPENTEST_LLM_MODE", "disabled").strip().lower(),
            base_url=os.getenv("AUTOPENTEST_LLM_BASE_URL"),
            model=os.getenv("AUTOPENTEST_LLM_MODEL"),
            api_key=os.getenv("AUTOPENTEST_LLM_API_KEY"),
            timeout_s=int(os.getenv("AUTOPENTEST_LLM_TIMEOUT_S", "30")),
        )


class StaticLLMClient:
    """Deterministic client for tests and offline demos."""

    def __init__(
        self,
        responses: Sequence[dict[str, Any] | str] | Callable[[str, str], dict[str, Any] | str],
    ) -> None:
        self._responses = responses
        self._cursor = 0

    def _next_payload(self, system_prompt: str, user_prompt: str) -> dict[str, Any] | str:
        if callable(self._responses):
            return self._responses(system_prompt, user_prompt)
        if self._cursor >= len(self._responses):
            raise LLMClientError("StaticLLMClient has no remaining responses.")
        payload = self._responses[self._cursor]
        self._cursor += 1
        return payload

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        del temperature
        payload = self._next_payload(system_prompt, user_prompt)
        if isinstance(payload, str):
            try:
                payload = json.loads(payload)
            except json.JSONDecodeError as exc:
                raise LLMClientError(f"StaticLLMClient returned invalid JSON: {exc}") from exc
        return schema.model_validate(_massage_payload_for_schema(payload, schema))


def _default_transport(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_s: int,
) -> dict[str, Any]:
    http_request = request.Request(url, data=body, headers=headers, method="POST")
    try:
        with request.urlopen(http_request, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8")
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        detail = response_body[:400] if response_body else str(exc)
        raise LLMClientError(f"LLM request failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise LLMClientError(f"LLM request failed: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LLMClientError(f"LLM server returned invalid JSON: {exc}") from exc


def _extract_balanced_json(text: str) -> str | None:
    """Return the first balanced JSON object/array found in *text*."""

    start = None
    opening = ""
    closing = ""
    depth = 0
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if start is None:
            if char == "{":
                start = index
                opening = "{"
                closing = "}"
                depth = 1
            elif char == "[":
                start = index
                opening = "["
                closing = "]"
                depth = 1
            continue

        if escaped:
            escaped = False
            continue
        if char == "\\" and in_string:
            escaped = True
            continue
        if char == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if char == opening:
            depth += 1
            continue
        if char == closing:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def _coerce_json_text(raw_text: str) -> str:
    """Normalize model text into a bare JSON payload when possible."""

    text = raw_text.strip()
    if not text:
        raise LLMClientError("LLM content is empty.")

    candidates: list[str] = [text]
    if text.startswith("```"):
        fenced = text.strip("` \n")
        if "\n" in fenced:
            _, _, remainder = fenced.partition("\n")
            candidates.append(remainder.strip())

    balanced = _extract_balanced_json(text)
    if balanced is not None:
        candidates.append(balanced.strip())

    for candidate in candidates:
        try:
            json.loads(candidate)
        except json.JSONDecodeError:
            continue
        return candidate

    snippet = text[:240].replace("\n", "\\n")
    raise LLMClientError(f"LLM content is not valid JSON: {snippet}")


class OpenAICompatibleLLMClient:
    """Structured-output client for OpenAI-compatible chat completion endpoints."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        timeout_s: int = 30,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.transport = transport or _default_transport

    def _extract_text_content(self, payload: dict[str, Any]) -> str:
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMClientError("LLM response is missing choices[0].message.content.") from exc

        if isinstance(content, str):
            return content
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    parts.append(str(item.get("text", "")))
            if parts:
                return "".join(parts)
        raise LLMClientError("LLM response content is not a supported text shape.")

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        payload = {
            "model": self.model,
            "temperature": temperature,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        body = json.dumps(payload).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        response_payload = self.transport(
            f"{self.base_url}/chat/completions",
            headers,
            body,
            self.timeout_s,
        )
        raw_text = self._extract_text_content(response_payload)
        try:
            structured = json.loads(_coerce_json_text(raw_text))
        except json.JSONDecodeError as exc:
            raise LLMClientError(f"LLM content is not valid JSON: {exc}") from exc
        return schema.model_validate(_massage_payload_for_schema(structured, schema))


def build_llm_client_from_env() -> LLMClient | None:
    """Construct an LLM client from environment variables."""

    settings = LLMSettings.from_env()
    if settings.mode in {"", "disabled", "off", "none"}:
        return None
    if settings.mode != "openai_compatible":
        raise LLMClientError(f"Unsupported AUTOPENTEST_LLM_MODE: {settings.mode}")
    if not settings.base_url or not settings.model or not settings.api_key:
        raise LLMClientError(
            "AUTOPENTEST_LLM_BASE_URL, AUTOPENTEST_LLM_MODEL, and AUTOPENTEST_LLM_API_KEY are required."
        )
    return OpenAICompatibleLLMClient(
        base_url=settings.base_url,
        model=settings.model,
        api_key=settings.api_key,
        timeout_s=settings.timeout_s,
    )
