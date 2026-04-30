"""Minimal structured-output LLM clients."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeVar, get_args, get_origin
from urllib import error, request

log = logging.getLogger(__name__)

from pydantic import BaseModel, ConfigDict, Field, ValidationError

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
    "solver_code": (
        "solver_code",
        "solverCode",
        "code",
        "script",
        "solution_code",
        "solutionCode",
        "solve_script",
        "solveScript",
        "exploit_code",
        "exploitCode",
    ),
    "solver_language": (
        "solver_language",
        "solverLanguage",
        "language",
        "lang",
    ),
    "task_type": ("task_type", "taskType", "type"),
    "title": ("title", "name", "label", "heading"),
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
        for key in ("path", "url", "route", "endpoint", "text", "summary", "description", "reason", "title", "value"):
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


def _list_inner_model(schema: type[BaseModel], field_name: str) -> type[BaseModel] | None:
    """Return the inner BaseModel type when *field_name* is ``list[SomeModel]``."""
    field_info = schema.model_fields.get(field_name)
    if field_info is None:
        return None
    annotation = field_info.annotation
    if get_origin(annotation) is not list:
        return None
    args = get_args(annotation)
    if not args:
        return None
    inner = args[0]
    if isinstance(inner, type) and issubclass(inner, BaseModel):
        return inner
    return None


def _coerce_json_object_for_schema(payload: Any, schema: type[ModelT]) -> Any:
    """When the API returns a JSON array (e.g. ``[null, ...]`` or ``[{...}, ...]``), pick a dict or fail closed."""

    if not isinstance(payload, list):
        return payload
    dict_items = [x for x in payload if isinstance(x, dict)]
    if dict_items:
        field_names = set(schema.model_fields)

        def score(candidate: dict[str, Any]) -> int:
            s = 0
            for field_name in field_names:
                if _lookup_value(candidate, field_name) is not None:
                    s += 2
            return s

        return max(dict_items, key=score)
    return {}


def _collect_code_like_strings(obj: Any, *, max_depth: int = 14) -> list[str]:
    """Walk nested JSON and find strings that look like Python solver code."""

    found: list[str] = []

    def walk(node: Any, depth: int) -> None:
        if depth > max_depth:
            return
        if isinstance(node, str):
            text = node.strip()
            if len(text) > 40 and ("import " in text or "\ndef " in text or "\nclass " in text):
                found.append(text)
        elif isinstance(node, dict):
            for value in node.values():
                walk(value, depth + 1)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item, depth + 1)

    walk(obj, 0)
    return found


def _massage_payload_for_schema(payload: Any, schema: type[ModelT]) -> Any:
    payload = _coerce_json_object_for_schema(payload, schema)
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
            "text_payloads",
            "query_variants",
            "filename_variants",
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

    # Recursively massage items inside list[BaseModel] fields
    for field_name in list(normalized.keys()):
        value = normalized[field_name]
        if not isinstance(value, list):
            continue
        inner_model = _list_inner_model(schema, field_name)
        if inner_model is None:
            continue
        normalized[field_name] = [
            _massage_payload_for_schema(item, inner_model)
            if isinstance(item, dict) else item
            for item in value
        ]

    # Synthesize missing required fields when enough context exists
    if "task_type" in field_names and "title" in field_names:
        task_type = normalized.get("task_type")
        if isinstance(task_type, str) and task_type.strip():
            if not normalized.get("title"):
                normalized["title"] = task_type.replace(".", " ").replace("_", " ").title()
            if "description" in field_names and not normalized.get("description"):
                normalized["description"] = (
                    f"Execute {task_type} as planned by the LLM planner."
                )

    # Synthesize solver_code when the LLM omits it but provides code-like content
    # elsewhere in the response (e.g. in summary or reasoning fields).
    if "solver_code" in field_names and not normalized.get("solver_code"):
        for key in ("reasoning", "summary", "explanation", "analysis"):
            candidate = normalized.get(key) or selected.get(key) or ""
            if isinstance(candidate, str) and ("import " in candidate or "def " in candidate or "print(" in candidate):
                # Looks like the LLM put code in a non-code field; extract it
                normalized["solver_code"] = candidate
                break

    if "solver_code" in field_names and not normalized.get("solver_code"):
        for text in _collect_code_like_strings(selected):
            normalized["solver_code"] = text
            break

    return normalized or selected


class TokenLedger:
    """Accumulates token usage across all LLM calls in one session."""

    def __init__(self) -> None:
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0
        self.llm_calls: int = 0

    def record(self, prompt: int, completion: int) -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.total_tokens += prompt + completion
        self.llm_calls += 1

    def to_dict(self) -> dict[str, int]:
        return {
            "llm_calls": self.llm_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }

    def __repr__(self) -> str:
        return (
            f"TokenLedger(calls={self.llm_calls}, "
            f"prompt={self.prompt_tokens}, "
            f"completion={self.completion_tokens}, "
            f"total={self.total_tokens})"
        )


class LLMClientError(RuntimeError):
    """Raised when an LLM call or response cannot be used safely."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


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


class _LLMPreflightResult(BaseModel):
    """Minimal structured response used to verify live LLM connectivity."""

    summary: str
    ok: bool = True


class LLMSettings(BaseModel):
    """Environment-backed configuration for LLM access."""

    model_config = ConfigDict(extra="ignore")

    mode: str = "disabled"
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    timeout_s: int = Field(default=30, ge=1)
    max_retries: int = Field(default=3, ge=0)
    max_completion_tokens: int = Field(default=16384, ge=1)

    @classmethod
    def from_env(cls) -> "LLMSettings":
        return cls(
            mode=os.getenv("AUTOPENTEST_LLM_MODE", "disabled").strip().lower(),
            base_url=os.getenv("AUTOPENTEST_LLM_BASE_URL"),
            model=os.getenv("AUTOPENTEST_LLM_MODEL"),
            api_key=os.getenv("AUTOPENTEST_LLM_API_KEY"),
            timeout_s=int(os.getenv("AUTOPENTEST_LLM_TIMEOUT_S", "30")),
            max_retries=int(os.getenv("AUTOPENTEST_LLM_MAX_RETRIES", "3")),
            max_completion_tokens=int(
                os.getenv("AUTOPENTEST_LLM_MAX_COMPLETION_TOKENS", "16384")
            ),
        )


class StaticLLMClient:
    """Deterministic client for tests and offline demos."""

    def __init__(
        self,
        responses: Sequence[dict[str, Any] | str] | Callable[[str, str], dict[str, Any] | str],
    ) -> None:
        self._responses = responses
        self._cursor = 0
        self.token_ledger = TokenLedger()

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
        massaged = _massage_payload_for_schema(payload, schema)
        if isinstance(massaged, dict) and "solver_code" in schema.model_fields:
            raw_code = massaged.get("solver_code")
            if not isinstance(raw_code, str) or not raw_code.strip():
                raise LLMClientError(
                    "LLM JSON missing non-empty solver_code field.",
                    transient=True,
                )
        try:
            return schema.model_validate(massaged)
        except ValidationError as exc:
            if "solver_code" in schema.model_fields:
                raise LLMClientError(
                    f"LLM response failed SolverCodeGuidance validation: {exc}",
                    transient=True,
                ) from exc
            raise LLMClientError(
                f"LLM response failed {schema.__name__} validation: {exc}"
            ) from exc


def _default_transport(
    url: str,
    headers: dict[str, str],
    body: bytes,
    timeout_s: int,
) -> dict[str, Any]:
    import socket

    http_request = request.Request(url, data=body, headers=headers, method="POST")
    old_default = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_s)
        with request.urlopen(http_request, timeout=timeout_s) as response:
            raw = response.read().decode("utf-8")
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        detail = response_body[:400] if response_body else str(exc)
        is_transient = exc.code in (429, 500, 502, 503, 504)
        raise LLMClientError(
            f"LLM request failed with HTTP {exc.code}: {detail}",
            transient=is_transient,
        ) from exc
    except error.URLError as exc:
        raise LLMClientError(
            f"LLM request failed: {exc}", transient=True,
        ) from exc
    except (socket.timeout, TimeoutError) as exc:
        raise LLMClientError(
            f"LLM request timed out after {timeout_s}s: {exc}", transient=True,
        ) from exc
    finally:
        socket.setdefaulttimeout(old_default)

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

    _RETRY_BASE_DELAY = 2.0
    _RETRY_MAX_DELAY = 60.0

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str,
        timeout_s: int = 30,
        max_retries: int = 3,
        max_completion_tokens: int = 16384,
        transport: Transport | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_completion_tokens = max_completion_tokens
        self.transport = transport or _default_transport
        self.token_ledger = TokenLedger()

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

    def _call_transport(self, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
        """Single HTTP call with retry on transient failures."""
        last_error: LLMClientError | None = None
        for attempt in range(1 + self.max_retries):
            try:
                return self.transport(
                    f"{self.base_url}/chat/completions",
                    headers,
                    body,
                    self.timeout_s,
                )
            except LLMClientError as exc:
                last_error = exc
                if not exc.transient or attempt >= self.max_retries:
                    raise
                delay = min(
                    self._RETRY_BASE_DELAY * (2 ** attempt),
                    self._RETRY_MAX_DELAY,
                )
                log.warning(
                    "LLM transient error (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1,
                    1 + self.max_retries,
                    delay,
                    exc,
                )
                time.sleep(delay)
        raise last_error  # type: ignore[misc]

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
            "response_format": {"type": "json_object"},
            "max_tokens": self.max_completion_tokens,
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
        response_payload = self._call_transport(body, headers)
        usage = response_payload.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 0)
        self.token_ledger.record(prompt_tokens, completion_tokens)
        log.info(
            "LLM call #%d: prompt=%d completion=%d total=%d (session total=%d)",
            self.token_ledger.llm_calls,
            prompt_tokens,
            completion_tokens,
            prompt_tokens + completion_tokens,
            self.token_ledger.total_tokens,
        )
        raw_text = self._extract_text_content(response_payload)
        try:
            structured = json.loads(_coerce_json_text(raw_text))
        except json.JSONDecodeError as exc:
            raise LLMClientError(f"LLM content is not valid JSON: {exc}") from exc
        massaged = _massage_payload_for_schema(structured, schema)
        if isinstance(massaged, dict) and "solver_code" in schema.model_fields:
            raw_code = massaged.get("solver_code")
            if not isinstance(raw_code, str) or not raw_code.strip():
                raise LLMClientError(
                    "LLM JSON missing non-empty solver_code field.",
                    transient=True,
                )
        try:
            return schema.model_validate(massaged)
        except ValidationError as exc:
            if "solver_code" in schema.model_fields:
                raise LLMClientError(
                    f"LLM response failed SolverCodeGuidance validation: {exc}",
                    transient=True,
                ) from exc
            raise LLMClientError(
                f"LLM response failed {schema.__name__} validation: {exc}"
            ) from exc


    def preflight(self) -> None:
        """Perform a small real request so runs fail before doing any work."""

        try:
            self.generate_json(
                system_prompt=(
                    "Return only a JSON object matching this schema: "
                    '{"summary": string, "ok": boolean}.'
                ),
                user_prompt='{"check": "connectivity", "expected": "json"}',
                schema=_LLMPreflightResult,
                temperature=0.0,
            )
        except LLMClientError:
            raise
        except Exception as exc:
            raise LLMClientError(f"LLM preflight failed: {type(exc).__name__}: {exc}") from exc


def build_llm_client_from_env(*, preflight: bool = True) -> LLMClient:
    """Construct an LLM client from environment variables.

    Raises LLMClientError if the environment is not properly configured.
    """

    settings = LLMSettings.from_env()
    if settings.mode in {"", "disabled", "off", "none"}:
        raise LLMClientError(
            "LLM is required but AUTOPENTEST_LLM_MODE is not set or is 'disabled'. "
            "Set AUTOPENTEST_LLM_MODE=openai_compatible and configure "
            "AUTOPENTEST_LLM_BASE_URL, AUTOPENTEST_LLM_MODEL, and AUTOPENTEST_LLM_API_KEY."
        )
    if settings.mode != "openai_compatible":
        raise LLMClientError(f"Unsupported AUTOPENTEST_LLM_MODE: {settings.mode}")
    if not settings.base_url or not settings.model or not settings.api_key:
        raise LLMClientError(
            "AUTOPENTEST_LLM_BASE_URL, AUTOPENTEST_LLM_MODEL, and AUTOPENTEST_LLM_API_KEY are required."
        )
    client = OpenAICompatibleLLMClient(
        base_url=settings.base_url,
        model=settings.model,
        api_key=settings.api_key,
        timeout_s=settings.timeout_s,
        max_retries=settings.max_retries,
        max_completion_tokens=settings.max_completion_tokens,
    )
    if preflight:
        client.preflight()
    return client
