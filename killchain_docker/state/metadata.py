"""Run metadata store for durable auxiliary state."""

from __future__ import annotations
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from killchain_docker.llm.gateway import LLMClientError
    from killchain_docker.state.run_state import RunState


class RunMetadataStore:
    """Mutable store for RunState metadata keys used by runtime modules."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def challenge(self) -> dict[str, Any]:
        payload = self.state.metadata.get("challenge", {}) or {}
        return dict(payload) if isinstance(payload, dict) else {}

    def challenge_name(self) -> str | None:
        challenge = self.challenge()
        value = challenge.get("canonical_name") or challenge.get("name")
        return str(value) if value else None

    def knowledge(self) -> object:
        return self.state.metadata.get("knowledge")

    def mutable_knowledge(self) -> dict[str, Any] | None:
        payload = self.state.metadata.setdefault("knowledge", {})
        return payload if isinstance(payload, dict) else None

    def runtime_error(self) -> dict[str, Any] | None:
        payload = self.state.metadata.get("runtime_error")
        return dict(payload) if isinstance(payload, dict) else None

    def remember_runtime_error(self, exc: BaseException) -> dict[str, str]:
        error = {
            "type": type(exc).__name__,
            "message": str(exc).strip() or type(exc).__name__,
        }
        self.state.metadata["runtime_error"] = error
        return error

    def remember_llm_error(
        self, *, cycle: int, source: str, exc: "LLMClientError", message: str
    ) -> dict[str, Any]:
        payload = {
            "cycle": cycle,
            "source": source,
            "kind": str(getattr(exc, "kind", "unknown")),
            "transient": bool(getattr(exc, "transient", False)),
            "schema_name": getattr(exc, "schema_name", None),
            "model": getattr(exc, "model", None),
            "attempts": getattr(exc, "attempts", None),
            "message": message,
        }
        self.state.metadata["last_llm_error"] = payload
        return payload

    def remember_transient_skip(
        self, *, cycle: int, source: str, exc: "LLMClientError"
    ) -> dict[str, Any]:
        payload = {
            "cycle": cycle,
            "source": source,
            "schema_name": getattr(exc, "schema_name", None),
            "model": getattr(exc, "model", None),
            "attempts": getattr(exc, "attempts", None),
        }
        self.state.metadata["last_transient_skip"] = payload
        return payload

    def consume_transient_skip(self) -> dict[str, Any] | None:
        payload = self.state.metadata.pop("last_transient_skip", None)
        return dict(payload) if isinstance(payload, dict) else None

    def forced_pivot(self) -> dict[str, Any] | None:
        payload = self.state.metadata.get("forced_pivot")
        return dict(payload) if isinstance(payload, dict) else None

    def set_forced_pivot(self, directive: dict[str, Any]) -> None:
        self.state.metadata["forced_pivot"] = directive

    def clear_forced_pivot(self) -> None:
        self.state.metadata.pop("forced_pivot", None)


__all__ = ["RunMetadataStore"]
