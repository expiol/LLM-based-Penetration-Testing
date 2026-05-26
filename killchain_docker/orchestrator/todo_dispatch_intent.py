"""Dispatch-intent payload mutation for planned todos."""

from __future__ import annotations

from killchain_docker.state.dispatch import DispatchIntent


def set_required_capability(
    context: dict[str, object], *, profile: str, capability: str
) -> None:
    raw_intent = context.get("dispatch_intent")
    intent = dict(raw_intent) if isinstance(raw_intent, dict) else {}
    intent["profile"] = profile
    intent["required_capability"] = capability
    intent.pop("completion_contract", None)
    intent.pop("repair_policy_id", None)
    context["dispatch_intent"] = intent


def dispatch_profile(context: dict[str, object], *, default: str) -> str:
    raw_intent = context.get("dispatch_intent")
    if isinstance(raw_intent, dict):
        profile = str(raw_intent.get("profile") or "").strip()
        if profile and profile != "open":
            return profile
    return default


def finalize_dispatch_intent(context: dict[str, object]) -> None:
    intent_payload = DispatchIntent.from_context(context).model_dump(
        mode="json", exclude_defaults=True
    )
    intent_payload.pop("completion_contract", None)
    intent_payload.pop("repair_policy_id", None)
    context["dispatch_intent"] = intent_payload
