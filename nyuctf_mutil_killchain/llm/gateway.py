"""Unified LLM gateway with instructor-based structured output."""

import json
import logging
import random
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

log = logging.getLogger(__name__)

ModelT = TypeVar("ModelT", bound=BaseModel)
FIXED_LLM_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "configs" / "mutil_killchain" / "llm_gateway.json"
)


class LLMClientError(RuntimeError):
    """Raised when an LLM call cannot be used safely."""

    def __init__(self, message: str, *, transient: bool = False) -> None:
        super().__init__(message)
        self.transient = transient


class LLMClient(Protocol):
    """Protocol for workers/planners that require structured output."""

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        """Return a response validated against the requested Pydantic schema."""


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


def _normalize_schema_model_map(payload: Any) -> dict[str, str]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise LLMClientError("schema_models must be a JSON object.")
    normalized: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not key.strip():
            continue
        if not isinstance(value, str) or not value.strip():
            continue
        normalized[key.strip()] = value.strip()
    return normalized


def _validate_model_names(default_model: str, schema_models: Mapping[str, str]) -> None:
    """Sanity-check model identifiers: non-empty strings only.

    The gateway speaks OpenAI-compatible HTTP, so any model id supported by the
    upstream provider is acceptable; we only reject blank/whitespace names.
    """
    if not default_model or not default_model.strip():
        raise LLMClientError("default_model must be a non-empty string.")
    for key, value in schema_models.items():
        if not isinstance(value, str) or not value.strip():
            raise LLMClientError(
                f"schema_models[{key!r}] must be a non-empty string."
            )


def _load_runtime_config_payload(path: Path) -> dict[str, Any]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LLMClientError(f"Cannot read LLM config file: {path} ({exc})") from exc
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise LLMClientError(f"LLM config file is not valid JSON: {path} ({exc})") from exc
    if not isinstance(payload, dict):
        raise LLMClientError(f"LLM config root must be JSON object: {path}")
    return payload


class LLMSettings(BaseModel):
    """Gateway settings loaded from configs/mutil_killchain/llm_gateway.json."""

    model_config = ConfigDict(extra="ignore")

    provider: str = "openai_compatible"
    base_url: str | None = None
    api_key: str | None = None
    default_model: str | None = Field(default=None, alias="model")
    schema_models: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = Field(default=60, ge=1)
    max_retries: int = Field(default=4, ge=0)
    max_completion_tokens: int = Field(default=16384, ge=1)

    @classmethod
    def from_env(cls) -> "LLMSettings":
        payload = _load_runtime_config_payload(FIXED_LLM_CONFIG_PATH)
        default_model = payload.get("default_model") or payload.get("model")
        schema_models = _normalize_schema_model_map(payload.get("schema_models"))
        if not default_model or not isinstance(default_model, str):
            raise LLMClientError("LLM default model is required (llm_gateway.json::default_model).")
        _validate_model_names(default_model.strip(), schema_models)

        resolved_api_key = str(payload.get("api_key") or "").strip()
        return cls(
            provider=str(payload.get("provider") or "openai_compatible").strip().lower(),
            base_url=payload.get("base_url"),
            api_key=(resolved_api_key or None),
            model=default_model.strip(),
            schema_models=schema_models,
            timeout_s=int(payload.get("timeout_s", 60)),
            max_retries=int(payload.get("max_retries", 4)),
            max_completion_tokens=int(payload.get("max_completion_tokens", 16384)),
        )


class _LLMPreflightResult(BaseModel):
    summary: str
    ok: bool = True


_PROVIDER_DEFAULT_BASE_URL: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "openai_compatible": "",
    "deepseek": "https://api.deepseek.com/v1",
    "together": "https://api.together.xyz/v1",
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
}


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
        try:
            return schema.model_validate(payload)
        except ValidationError as exc:
            raise LLMClientError(
                f"LLM response failed {schema.__name__} validation: {exc}"
            ) from exc


class GatewayLLMClient:
    """Unified gateway that parses directly into Pydantic schemas via instructor."""

    _RETRY_BASE_DELAY = 3.0
    _RETRY_MAX_DELAY = 90.0
    _RETRY_JITTER_FRAC = 0.2

    def __init__(
        self,
        *,
        provider: str,
        api_key: str,
        default_model: str,
        schema_models: Mapping[str, str] | None = None,
        base_url: str | None = None,
        timeout_s: int = 60,
        max_retries: int = 4,
        max_completion_tokens: int = 16384,
    ) -> None:
        self.provider = provider.strip().lower()
        self.api_key = api_key
        self.default_model = default_model.strip()
        self.schema_models = dict(schema_models or {})
        self.base_url = (base_url or _PROVIDER_DEFAULT_BASE_URL.get(self.provider) or "").rstrip("/")
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.max_completion_tokens = max_completion_tokens
        _validate_model_names(self.default_model, self.schema_models)
        self.token_ledger = TokenLedger()
        self._client = self._build_client()

    def _build_client(self) -> Any:
        try:
            import instructor
        except ImportError as exc:
            raise LLMClientError(
                "Gateway mode requires 'instructor'. Install dependencies first."
            ) from exc
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMClientError("Gateway mode requires 'openai'.") from exc

        kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "timeout": self.timeout_s,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url
        raw = OpenAI(**kwargs)
        # DeepSeek's reasoner-class models (which back v4-flash / v4-pro on
        # api.deepseek.com) reject the function-calling ``tool_choice`` that
        # instructor sends in its default Mode.TOOLS path. JSON mode enforces
        # the schema via response_format + prompt injection and works on
        # every OpenAI-compatible backend we use.
        return instructor.from_openai(raw, mode=instructor.Mode.JSON)

    def _select_model(self, schema: type[BaseModel]) -> str:
        schema_name = schema.__name__
        for candidate in (schema_name, schema_name.lower(), "*"):
            model = self.schema_models.get(candidate)
            if model:
                return model
        return self.default_model

    def _is_transient(self, exc: Exception) -> bool:
        message = str(exc).lower()
        markers = (
            "rate limit", "429", "timeout", "timed out", "temporarily",
            "connection", "service unavailable", "502", "503", "504",
        )
        if any(marker in message for marker in markers):
            return True
        name = type(exc).__name__.lower()
        return "timeout" in name or "ratelimit" in name or "connection" in name

    def _record_usage(self, completion: Any) -> None:
        usage = getattr(completion, "usage", None)
        if usage is None and isinstance(completion, dict):
            usage = completion.get("usage")
        if usage is None:
            self.token_ledger.record(0, 0)
            return

        def _usage_get(name: str) -> int:
            if isinstance(usage, dict):
                return int(usage.get(name) or 0)
            return int(getattr(usage, name, 0) or 0)

        prompt_tokens = _usage_get("prompt_tokens")
        completion_tokens = _usage_get("completion_tokens")
        self.token_ledger.record(prompt_tokens, completion_tokens)
        log.info(
            "LLM call #%d model=%s prompt=%d completion=%d total=%d",
            self.token_ledger.llm_calls,
            getattr(completion, "model", "unknown"),
            prompt_tokens,
            completion_tokens,
            prompt_tokens + completion_tokens,
        )

    def _create_structured(
        self,
        *,
        messages: list[dict[str, str]],
        schema: type[ModelT],
        model: str,
        temperature: float,
    ) -> tuple[ModelT, Any | None]:
        endpoint = self._client.chat.completions
        kwargs: dict[str, Any] = {
            "model": model,
            "response_model": schema,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_completion_tokens,
        }
        if hasattr(endpoint, "create_with_completion"):
            parsed, completion = endpoint.create_with_completion(**kwargs)
            return parsed, completion
        parsed = endpoint.create(**kwargs)
        return parsed, None

    def generate_json(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        selected_model = self._select_model(schema)
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]
        last_exc: Exception | None = None
        for attempt in range(1 + self.max_retries):
            try:
                parsed, completion = self._create_structured(
                    messages=messages, schema=schema, model=selected_model, temperature=temperature
                )
                self._record_usage(completion)
                return parsed
            except Exception as exc:
                last_exc = exc
                transient = self._is_transient(exc)
                if not transient or attempt >= self.max_retries:
                    break
                base_delay = min(self._RETRY_BASE_DELAY * (2 ** attempt), self._RETRY_MAX_DELAY)
                jitter = base_delay * self._RETRY_JITTER_FRAC
                delay = max(0.1, base_delay + random.uniform(-jitter, jitter))
                log.warning(
                    "Gateway transient error (attempt %d/%d), retrying in %.1fs: %s",
                    attempt + 1,
                    1 + self.max_retries,
                    delay,
                    exc,
                )
                time.sleep(delay)

        assert last_exc is not None
        raise LLMClientError(
            f"Gateway structured output failed for {schema.__name__} (model={selected_model}): {last_exc}",
            transient=self._is_transient(last_exc),
        ) from last_exc

    def preflight(self) -> None:
        self.generate_json(
            system_prompt=(
                "Return only a JSON object matching this schema: "
                '{"summary": string, "ok": boolean}.'
            ),
            user_prompt='{"check":"connectivity"}',
            schema=_LLMPreflightResult,
            temperature=0.0,
        )


def build_llm_client_from_env(*, preflight: bool = True) -> LLMClient:
    """Construct the gateway client from fixed JSON config."""

    settings = LLMSettings.from_env()
    if not settings.api_key:
        raise LLMClientError(f"'api_key' is required in {FIXED_LLM_CONFIG_PATH}.")
    if not settings.default_model:
        raise LLMClientError(f"'default_model' is required in {FIXED_LLM_CONFIG_PATH}.")

    client = GatewayLLMClient(
        provider=settings.provider,
        api_key=settings.api_key,
        default_model=settings.default_model,
        schema_models=settings.schema_models,
        base_url=settings.base_url,
        timeout_s=settings.timeout_s,
        max_retries=settings.max_retries,
        max_completion_tokens=settings.max_completion_tokens,
    )
    if preflight:
        client.preflight()
    return client
