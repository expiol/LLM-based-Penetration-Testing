"""Structured todo dispatch intent."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator

from killchain_docker.state.common import coerce_text_items, parse_text_sequence


class DispatchIntent(BaseModel):
    """Machine-readable routing and execution intent for a todo."""

    profile: str = "open"
    required_capability: str | None = None
    allowed_capabilities: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    target_refs: dict[str, Any] = Field(default_factory=dict)
    completion_contract: list[str] = Field(default_factory=list)
    repair_policy_id: str | None = None

    @field_validator("profile", mode="before")
    @classmethod
    def _coerce_profile(cls, value: Any) -> str:
        from killchain_docker.tools.capabilities import normalize_dispatch_profile

        return normalize_dispatch_profile(value)

    @field_validator("required_capability", "repair_policy_id", mode="before")
    @classmethod
    def _coerce_optional_text(cls, value: Any) -> str | None:
        if value in (None, "", [], {}, ()):
            return None
        return str(value).strip() or None

    @field_validator(
        "allowed_capabilities", "evidence_ids", "completion_contract", mode="before"
    )
    @classmethod
    def _coerce_text_list(cls, value: Any) -> list[str]:
        if value in (None, "", {}, ()):
            return []
        if isinstance(value, (list, tuple, set)):
            return coerce_text_items(value)
        text = str(value).strip()
        parsed = parse_text_sequence(text)
        if parsed is not None:
            return coerce_text_items(parsed)
        return [text] if text else []

    @classmethod
    def from_context(cls, context: dict[str, Any] | None) -> "DispatchIntent":
        context = context or {}
        raw = context.get("dispatch_intent")
        if isinstance(raw, DispatchIntent):
            return raw
        payload = dict(raw) if isinstance(raw, dict) else {}

        capability = str(payload.get("required_capability") or "").strip()

        evidence_ids = payload.get("evidence_ids") or context.get("evidence_ids")
        if evidence_ids and "evidence_ids" not in payload:
            payload["evidence_ids"] = evidence_ids

        if not isinstance(payload.get("target_refs"), dict):
            payload.pop("target_refs", None)

        if "profile" not in payload:
            payload["profile"] = cls._profile_from_context(context, capability)
        else:
            from killchain_docker.tools.capabilities import normalize_dispatch_profile

            payload["profile"] = normalize_dispatch_profile(payload.get("profile"))

        return cls.model_validate(payload)

    @staticmethod
    def _profile_from_context(context: dict[str, Any], capability: str) -> str:
        from killchain_docker.tools.capabilities import dispatch_profile_for_family

        family = str(context.get("family") or "").strip().lower()
        if capability:
            from killchain_docker.tools.capabilities import (
                dispatch_profile_for_capability,
            )

            capability_profile = dispatch_profile_for_capability(capability)
            if capability_profile != "open":
                return capability_profile
        family_profile = dispatch_profile_for_family(family)
        if family_profile != "open":
            return family_profile
        if context.get("candidate_flag"):
            return "flag_validation"
        if context.get("scope") or context.get("base_url") or context.get("url"):
            return "scope_mapping"
        return "open"
