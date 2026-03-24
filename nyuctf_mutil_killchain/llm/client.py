"""Minimal structured-output LLM clients."""

from __future__ import annotations

import json
import os
from collections.abc import Callable, Sequence
from typing import Any, Protocol, TypeVar
from urllib import error, request

from pydantic import BaseModel, ConfigDict, Field

ModelT = TypeVar("ModelT", bound=BaseModel)
Transport = Callable[[str, dict[str, str], bytes, int], dict[str, Any]]


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
        return schema.model_validate(payload)


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
        return schema.model_validate(structured)


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
