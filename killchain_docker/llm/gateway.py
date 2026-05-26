"""Unified LLM gateway with raw OpenAI-client structured output.

The gateway owns the success-path JSON repair and the correction-prompt retry
that feeds validator feedback back to the model.  Decoding is deliberately
separate from transport so failures stay observable and the retry policy lives
in one place (``generate_json``).
"""

import json
import logging
import random
import signal
import threading
import time
from contextlib import contextmanager
from collections.abc import Callable, Mapping, Sequence
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from killchain_docker.llm.structured_output import (
    completion_content,
    loads_lenient_json_object,
)

log = logging.getLogger(__name__)

ModelT = TypeVar("ModelT", bound=BaseModel)
FIXED_LLM_CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "configs" / "llm_gateway.json"
)
SCHEMA_MAX_COMPLETION_TOKENS = {
    "ToolUseDecision": 12000,
}
SCHEMA_REQUEST_TIMEOUT_S = {
    "ToolUseDecision": 45.0,
}
SCHEMA_TOTAL_DEADLINE_S = {
    "ToolUseDecision": 90.0,
}


class LLMClientError(RuntimeError):
    """Raised when an LLM call cannot be used safely."""

    def __init__(
        self,
        message: str,
        *,
        transient: bool = False,
        kind: "LLMFailureKind | str | None" = None,
        schema_name: str | None = None,
        model: str | None = None,
        attempts: int | None = None,
    ) -> None:
        super().__init__(message)
        self.kind = (
            LLMFailureKind.coerce(kind)
            if kind is not None
            else (LLMFailureKind.TRANSIENT if transient else LLMFailureKind.UNKNOWN)
        )
        self.transient = transient or self.kind.is_transient
        self.schema_name = schema_name
        self.model = model
        self.attempts = attempts


class LLMFailureKind(StrEnum):
    """Typed LLM failure reason used for retry and run-state reporting."""

    CONFIG = "config"
    CONNECTION = "connection"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    DEPENDENCY = "dependency"
    RATE_LIMIT = "rate_limit"
    SCHEMA_VALIDATION = "schema_validation"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TIMEOUT = "timeout"
    TRANSIENT = "transient"
    UNKNOWN = "unknown"

    @property
    def is_transient(self) -> bool:
        """Should the gateway *re-issue* the request for this kind?

        Transient = transport-level — request never produced usable output, so
        retrying the same messages may succeed.  Schema validation does NOT
        belong here: the gateway already did its in-call correction-prompt
        attempt, and re-issuing the same prompt is wasteful.
        """

        return self in {
            LLMFailureKind.CONNECTION,
            LLMFailureKind.DEADLINE_EXCEEDED,
            LLMFailureKind.RATE_LIMIT,
            LLMFailureKind.SERVICE_UNAVAILABLE,
            LLMFailureKind.TIMEOUT,
            LLMFailureKind.TRANSIENT,
        }

    @classmethod
    def coerce(cls, value: "LLMFailureKind | str | None") -> "LLMFailureKind":
        if isinstance(value, LLMFailureKind):
            return value
        if value is None:
            return cls.UNKNOWN
        try:
            return cls(str(value))
        except ValueError:
            return cls.UNKNOWN


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
        self._lock = threading.Lock()
        self._prompt_tokens: int = 0
        self._completion_tokens: int = 0
        self._total_tokens: int = 0
        self._llm_calls: int = 0

    @property
    def prompt_tokens(self) -> int:
        return self.to_dict()["prompt_tokens"]

    @property
    def completion_tokens(self) -> int:
        return self.to_dict()["completion_tokens"]

    @property
    def total_tokens(self) -> int:
        return self.to_dict()["total_tokens"]

    @property
    def llm_calls(self) -> int:
        return self.to_dict()["llm_calls"]

    def record(self, prompt: int, completion: int) -> dict[str, int]:
        with self._lock:
            self._prompt_tokens += prompt
            self._completion_tokens += completion
            self._total_tokens += prompt + completion
            self._llm_calls += 1
            return self._snapshot_unlocked()

    def to_dict(self) -> dict[str, int]:
        with self._lock:
            return self._snapshot_unlocked()

    def _snapshot_unlocked(self) -> dict[str, int]:
        return {
            "llm_calls": self._llm_calls,
            "prompt_tokens": self._prompt_tokens,
            "completion_tokens": self._completion_tokens,
            "total_tokens": self._total_tokens,
        }


def _normalize_schema_model_map(payload: Any) -> dict[str, str]:
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise LLMClientError(
            "schema_models must be a JSON object.",
            kind=LLMFailureKind.CONFIG,
        )
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
        raise LLMClientError(
            "default_model must be a non-empty string.",
            kind=LLMFailureKind.CONFIG,
        )
    for key, value in schema_models.items():
        if not isinstance(value, str) or not value.strip():
            raise LLMClientError(
                f"schema_models[{key!r}] must be a non-empty string.",
                kind=LLMFailureKind.CONFIG,
            )


def _load_runtime_config_payload(path: Path) -> dict[str, Any]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise LLMClientError(
            f"Cannot read LLM config file: {path} ({exc})",
            kind=LLMFailureKind.CONFIG,
        ) from exc
    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise LLMClientError(
            f"LLM config file is not valid JSON: {path} ({exc})",
            kind=LLMFailureKind.CONFIG,
        ) from exc
    if not isinstance(payload, dict):
        raise LLMClientError(
            f"LLM config root must be JSON object: {path}",
            kind=LLMFailureKind.CONFIG,
        )
    return payload


def _config_int(payload: dict[str, Any], key: str, default: int | None) -> int | None:
    value = payload.get(key, default)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise LLMClientError(
            f"LLM config field {key!r} must be an integer.",
            kind=LLMFailureKind.CONFIG,
        ) from exc


class LLMSettings(BaseModel):
    """Gateway settings loaded from configs/llm_gateway.json."""

    model_config = ConfigDict(extra="ignore")

    provider: str = "openai_compatible"
    base_url: str | None = None
    api_key: str | None = None
    default_model: str | None = Field(default=None)
    schema_models: dict[str, str] = Field(default_factory=dict)
    timeout_s: int = Field(default=60, ge=1)
    max_retries: int = Field(default=4, ge=0)
    total_deadline_s: int | None = Field(default=None, ge=1)
    max_completion_tokens: int = Field(default=16384, ge=1)

    @classmethod
    def from_env(cls) -> "LLMSettings":
        payload = _load_runtime_config_payload(FIXED_LLM_CONFIG_PATH)
        configured_default = payload.get("default_model")
        schema_models = _normalize_schema_model_map(payload.get("schema_models"))
        if not configured_default or not isinstance(configured_default, str):
            raise LLMClientError(
                "LLM default model is required (llm_gateway.json::default_model).",
                kind=LLMFailureKind.CONFIG,
            )
        _validate_model_names(configured_default.strip(), schema_models)

        resolved_api_key = str(payload.get("api_key") or "").strip()
        try:
            return cls(
                provider=str(payload.get("provider") or "openai_compatible")
                .strip()
                .lower(),
                base_url=payload.get("base_url"),
                api_key=(resolved_api_key or None),
                default_model=configured_default.strip(),
                schema_models=schema_models,
                timeout_s=_config_int(payload, "timeout_s", 60),
                max_retries=_config_int(payload, "max_retries", 4),
                total_deadline_s=_config_int(payload, "total_deadline_s", None),
                max_completion_tokens=_config_int(
                    payload, "max_completion_tokens", 16384
                ),
            )
        except ValidationError as exc:
            raise LLMClientError(
                f"LLM config validation failed: {exc}",
                kind=LLMFailureKind.CONFIG,
            ) from exc


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
        responses: Sequence[dict[str, Any] | str]
        | Callable[[str, str], dict[str, Any] | str],
    ) -> None:
        self._responses = responses
        self._cursor = 0
        self.token_ledger = TokenLedger()

    def _next_payload(
        self, system_prompt: str, user_prompt: str
    ) -> dict[str, Any] | str:
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
                payload = loads_lenient_json_object(payload)
            except json.JSONDecodeError as exc:
                raise LLMClientError(
                    f"StaticLLMClient returned invalid JSON: {exc}",
                    kind=LLMFailureKind.SCHEMA_VALIDATION,
                ) from exc
        try:
            return schema.model_validate(payload)
        except ValidationError as exc:
            raise LLMClientError(
                f"LLM response failed {schema.__name__} validation: {exc}",
                kind=LLMFailureKind.SCHEMA_VALIDATION,
                schema_name=schema.__name__,
            ) from exc


class GatewayLLMClient:
    """Unified gateway that parses raw OpenAI JSON responses into Pydantic schemas."""

    _RETRY_BASE_DELAY = 3.0
    _RETRY_MAX_DELAY = 90.0
    _RETRY_JITTER_FRAC = 0.2
    _MAX_CORRECTION_PROMPT_BYTES = 8000

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
        total_deadline_s: int | None = None,
        max_completion_tokens: int = 16384,
    ) -> None:
        self.provider = provider.strip().lower()
        self.api_key = api_key
        self.default_model = default_model.strip()
        self.schema_models = dict(schema_models or {})
        self.base_url = (
            base_url or _PROVIDER_DEFAULT_BASE_URL.get(self.provider) or ""
        ).rstrip("/")
        self.timeout_s = timeout_s
        self.max_retries = max_retries
        self.total_deadline_s = total_deadline_s
        self.max_completion_tokens = max_completion_tokens
        _validate_model_names(self.default_model, self.schema_models)
        self.token_ledger = TokenLedger()
        self._client = self._build_client()

    def _build_client(self) -> Any:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise LLMClientError(
                "Gateway mode requires 'openai'.",
                kind=LLMFailureKind.DEPENDENCY,
            ) from exc

        kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "timeout": self.timeout_s,
            "max_retries": 0,
        }
        if self.base_url:
            kwargs["base_url"] = self.base_url
        # max_retries=0: retries are owned by generate_json(), not by the
        # OpenAI client, so we keep one centralised retry policy.  We use the
        # raw client (not instructor) and run repair + validation ourselves on
        # the success path so the JSON-coercion pipeline is observable.
        return OpenAI(**kwargs)

    def _decode_into_schema(
        self, content: str, schema: type[ModelT]
    ) -> ModelT:
        """Repair-then-validate raw model JSON against a pydantic schema.

        Raises ``LLMClientError(SCHEMA_VALIDATION)`` if the content is not a
        decodable JSON object or does not satisfy the schema.  The exception
        carries the offending content so callers can build a correction prompt.
        """

        if not content or not content.strip():
            raise LLMClientError(
                f"empty response for {schema.__name__}",
                kind=LLMFailureKind.SCHEMA_VALIDATION,
                schema_name=schema.__name__,
            )
        try:
            payload = loads_lenient_json_object(content)
        except (json.JSONDecodeError, ValueError) as exc:
            error = LLMClientError(
                f"JSON decode failed for {schema.__name__}: {exc}",
                kind=LLMFailureKind.SCHEMA_VALIDATION,
                schema_name=schema.__name__,
            )
            error.raw_content = content  # type: ignore[attr-defined]
            error.validator_message = str(exc)  # type: ignore[attr-defined]
            raise error from exc
        try:
            return schema.model_validate(payload)
        except ValidationError as exc:
            summary = self._summarise_validation_errors(exc)
            error = LLMClientError(
                f"{schema.__name__} validation failed: {exc.error_count()} error(s); {summary}",
                kind=LLMFailureKind.SCHEMA_VALIDATION,
                schema_name=schema.__name__,
            )
            error.raw_content = content  # type: ignore[attr-defined]
            error.validator_message = summary  # type: ignore[attr-defined]
            raise error from exc

    @staticmethod
    def _summarise_validation_errors(exc: ValidationError) -> str:
        lines: list[str] = []
        for err in exc.errors():
            loc = ".".join(str(part) for part in err.get("loc", ()))
            msg = err.get("msg", "invalid")
            lines.append(f"- {loc or '<root>'}: {msg}")
        return "\n".join(lines) or str(exc)

    @staticmethod
    def _truncate_for_prompt(content: str, max_bytes: int) -> str:
        if len(content) <= max_bytes:
            return content
        head = content[: max_bytes // 2]
        tail = content[-max_bytes // 2 :]
        return f"{head}\n... [truncated {len(content) - max_bytes} chars] ...\n{tail}"

    def _build_correction_messages(
        self,
        *,
        original: list[dict[str, str]],
        bad_content: str,
        validator_message: str,
        schema: type[ModelT],
    ) -> list[dict[str, str]]:
        """Append assistant + user turns asking the model to fix its prior reply."""

        assistant_payload = self._truncate_for_prompt(
            bad_content, self._MAX_CORRECTION_PROMPT_BYTES
        )
        feedback = (
            f"Your previous reply did not satisfy the {schema.__name__} schema.\n"
            f"Validator feedback:\n{validator_message}\n\n"
            "Reply again with a single JSON object that fully satisfies the schema. "
            "Do not apologise, do not add prose, and do not wrap the JSON in code "
            "fences. Re-emit any unchanged fields verbatim."
        )
        return [
            *original,
            {"role": "assistant", "content": assistant_payload},
            {"role": "user", "content": feedback},
        ]

    def _create_structured(
        self,
        *,
        messages: list[dict[str, str]],
        schema: type[ModelT],
        model: str,
        temperature: float,
        request_timeout_s: float | None = None,
    ) -> tuple[ModelT, Any | None]:
        """Issue one chat completion request and decode it.

        On schema-validation failure, makes one in-call correction-prompt
        attempt with the offending content + validator message embedded.  On
        transport failure, propagates the exception so ``generate_json`` can
        decide whether to retry.
        """

        endpoint = self._client.chat.completions
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self._max_tokens_for_schema(schema),
            "response_format": {"type": "json_object"},
        }
        if request_timeout_s is not None:
            kwargs["timeout"] = request_timeout_s

        completion = endpoint.create(**kwargs)
        content = completion_content(completion) or ""
        try:
            return self._decode_into_schema(content, schema), completion
        except LLMClientError as exc:
            if exc.kind is not LLMFailureKind.SCHEMA_VALIDATION:
                raise
            log.info(
                "structured output failed; sending correction prompt",
                extra={
                    "schema": schema.__name__,
                    "model": model,
                    "validator": getattr(exc, "validator_message", ""),
                },
            )
            corrected_messages = self._build_correction_messages(
                original=messages,
                bad_content=getattr(exc, "raw_content", content) or content,
                validator_message=getattr(exc, "validator_message", "") or str(exc),
                schema=schema,
            )
            corrected_kwargs = dict(kwargs)
            corrected_kwargs["messages"] = corrected_messages
            corrected_kwargs["temperature"] = max(0.0, temperature * 0.5)
            corrected = endpoint.create(**corrected_kwargs)
            corrected_content = completion_content(corrected) or ""
            parsed = self._decode_into_schema(corrected_content, schema)
            return parsed, corrected

    def _select_model(self, schema: type[BaseModel]) -> str:
        schema_name = schema.__name__
        for candidate in (schema_name, schema_name.lower(), "*"):
            model = self.schema_models.get(candidate)
            if model:
                return model
        return self.default_model

    def _is_schema_validation_error(self, exc: Exception) -> bool:
        if isinstance(exc, ValidationError):
            return True
        message = str(exc).lower()
        validation_markers = (
            "validation error for",
            "pydantic.dev",
            "response validation",
            "failed validation",
            "json decode",
            "invalid json",
        )
        if any(marker in message for marker in validation_markers):
            return True
        name = type(exc).__name__.lower()
        return "validation" in name or "jsondecode" in name

    def _classify_failure(self, exc: Exception) -> LLMFailureKind:
        if isinstance(exc, LLMClientError):
            return exc.kind
        if self._is_schema_validation_error(exc):
            return LLMFailureKind.SCHEMA_VALIDATION
        message = str(exc).lower()
        if "rate limit" in message or "429" in message:
            return LLMFailureKind.RATE_LIMIT
        if "timeout" in message or "timed out" in message:
            return LLMFailureKind.TIMEOUT
        if "connection" in message:
            return LLMFailureKind.CONNECTION
        if (
            "service unavailable" in message
            or "502" in message
            or "503" in message
            or "504" in message
        ):
            return LLMFailureKind.SERVICE_UNAVAILABLE
        if "temporarily" in message:
            return LLMFailureKind.TRANSIENT
        name = type(exc).__name__.lower()
        if "ratelimit" in name:
            return LLMFailureKind.RATE_LIMIT
        if "timeout" in name:
            return LLMFailureKind.TIMEOUT
        if "connection" in name:
            return LLMFailureKind.CONNECTION
        return LLMFailureKind.UNKNOWN

    def _is_transient(self, exc: Exception) -> bool:
        return self._classify_failure(exc).is_transient

    def _record_usage(self, completion: Any, *, schema_name: str, model: str) -> None:
        usage = getattr(completion, "usage", None)
        if usage is None and isinstance(completion, dict):
            usage = completion.get("usage")
        if usage is None:
            token_usage = self.token_ledger.record(0, 0)
            self._log_usage(
                schema_name=schema_name,
                model=model,
                llm_call=token_usage["llm_calls"],
                prompt_tokens=0,
                completion_tokens=0,
                usage_available=False,
            )
            return

        def _usage_get(name: str) -> int:
            if isinstance(usage, dict):
                return int(usage.get(name) or 0)
            return int(getattr(usage, name, 0) or 0)

        prompt_tokens = _usage_get("prompt_tokens")
        completion_tokens = _usage_get("completion_tokens")
        token_usage = self.token_ledger.record(prompt_tokens, completion_tokens)
        completion_model = getattr(completion, "model", None)
        self._log_usage(
            schema_name=schema_name,
            model=str(completion_model or model or "unknown"),
            llm_call=token_usage["llm_calls"],
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            usage_available=True,
        )

    def _log_usage(
        self,
        *,
        schema_name: str,
        model: str,
        llm_call: int,
        prompt_tokens: int,
        completion_tokens: int,
        usage_available: bool,
    ) -> None:
        total_tokens = prompt_tokens + completion_tokens
        log.info(
            "LLM call completed",
            extra={
                "schema": schema_name,
                "model": model,
                "llm_call": llm_call,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
                "usage_available": usage_available,
            },
        )

    @contextmanager
    def _hard_request_deadline(self, timeout_s: float):
        if (
            timeout_s <= 0
            or not hasattr(signal, "SIGALRM")
            or threading.current_thread() is not threading.main_thread()
        ):
            yield
            return

        prior_handler = signal.getsignal(signal.SIGALRM)
        prior_timer = signal.getitimer(signal.ITIMER_REAL)
        prior_delay, _prior_interval = prior_timer
        if prior_delay > 0:
            yield
            return
        effective_timeout = float(timeout_s)

        def _raise_timeout(_signum: int, _frame: Any) -> None:
            raise TimeoutError(
                f"LLM request exceeded {effective_timeout:.1f}s hard deadline"
            )

        signal.signal(signal.SIGALRM, _raise_timeout)
        signal.setitimer(signal.ITIMER_REAL, effective_timeout)
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior_handler)

    def _max_tokens_for_schema(self, schema: type[BaseModel]) -> int:
        cap = SCHEMA_MAX_COMPLETION_TOKENS.get(schema.__name__)
        if cap is None:
            return self.max_completion_tokens
        return max(1, min(self.max_completion_tokens, cap))

    def _request_timeout_s_for_schema(self, schema: type[BaseModel]) -> float:
        cap = SCHEMA_REQUEST_TIMEOUT_S.get(schema.__name__)
        if cap is None:
            return float(self.timeout_s)
        return max(0.1, min(float(self.timeout_s), cap))

    def _call_deadline_s(self, schema: type[BaseModel] | None = None) -> float:
        if schema is None:
            retry_budget = float(self.timeout_s * (1 + self.max_retries))
            if self.total_deadline_s is None:
                return retry_budget
            return min(float(self.total_deadline_s), retry_budget)
        retry_budget = self._request_timeout_s_for_schema(schema) * (
            1 + self.max_retries
        )
        deadline = self.total_deadline_s
        schema_deadline = SCHEMA_TOTAL_DEADLINE_S.get(schema.__name__)
        if schema_deadline is not None:
            deadline = (
                schema_deadline
                if deadline is None
                else min(float(deadline), schema_deadline)
            )
        if deadline is None:
            return retry_budget
        return min(float(deadline), retry_budget)

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
        # Total deadline across all retry attempts so a single generate_json
        # call never blocks a worker indefinitely.
        max_retries = self.max_retries
        deadline = time.monotonic() + self._call_deadline_s(schema)
        last_exc: Exception | None = None
        attempts_used = 0
        for attempt in range(1 + max_retries):
            remaining_s = deadline - time.monotonic()
            if remaining_s <= 0:
                break
            try:
                attempts_used += 1
                request_timeout_s = max(
                    0.1, min(self._request_timeout_s_for_schema(schema), remaining_s)
                )
                with self._hard_request_deadline(request_timeout_s):
                    parsed, completion = self._create_structured(
                        messages=messages,
                        schema=schema,
                        model=selected_model,
                        temperature=temperature,
                        request_timeout_s=request_timeout_s,
                    )
                self._record_usage(
                    completion,
                    schema_name=schema.__name__,
                    model=selected_model,
                )
                return parsed
            except Exception as exc:
                last_exc = exc
                transient = self._is_transient(exc)
                if not transient or attempt >= max_retries:
                    break
                base_delay = min(
                    self._RETRY_BASE_DELAY * (2**attempt), self._RETRY_MAX_DELAY
                )
                jitter = base_delay * self._RETRY_JITTER_FRAC
                delay = max(0.1, base_delay + random.uniform(-jitter, jitter))
                if delay >= deadline - time.monotonic():
                    break
                log.warning(
                    "gateway transient error; retrying",
                    exc_info=True,
                    extra={
                        "attempt": attempt + 1,
                        "attempts": 1 + max_retries,
                        "retry_delay_s": round(delay, 3),
                        "schema": schema.__name__,
                        "model": selected_model,
                        "error_type": type(exc).__name__,
                    },
                )
                time.sleep(delay)

        if last_exc is None:
            last_exc = TimeoutError("generate_json exceeded deadline")
        kind = self._classify_failure(last_exc)
        log.error(
            "gateway structured output failed",
            exc_info=(type(last_exc), last_exc, last_exc.__traceback__),
            extra={
                "schema": schema.__name__,
                "model": selected_model,
                "failure_kind": str(kind),
                "error_type": type(last_exc).__name__,
                "attempts": attempts_used,
                "max_retries": max_retries,
            },
        )
        raise LLMClientError(
            f"Gateway structured output failed for {schema.__name__} (model={selected_model}): {last_exc}",
            kind=kind,
            schema_name=schema.__name__,
            model=selected_model,
            attempts=attempts_used,
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
        raise LLMClientError(
            f"'api_key' is required in {FIXED_LLM_CONFIG_PATH}.",
            kind=LLMFailureKind.CONFIG,
        )
    if not settings.default_model:
        raise LLMClientError(
            f"'default_model' is required in {FIXED_LLM_CONFIG_PATH}.",
            kind=LLMFailureKind.CONFIG,
        )

    client = GatewayLLMClient(
        provider=settings.provider,
        api_key=settings.api_key,
        default_model=settings.default_model,
        schema_models=settings.schema_models,
        base_url=settings.base_url,
        timeout_s=settings.timeout_s,
        max_retries=settings.max_retries,
        total_deadline_s=settings.total_deadline_s,
        max_completion_tokens=settings.max_completion_tokens,
    )
    if preflight:
        client.preflight()
    return client
