"""Public knowledge payload — the audit-safe view exposed in run summaries."""

from __future__ import annotations

from typing import Any


_ALLOWED_STATUS = {
    "hit",
    "miss",
    "empty_query",
    "disabled",
    "unavailable",
    "error",
    "pending",
}


def public_knowledge_payload(payload: object) -> dict[str, Any] | None:
    """Return user-facing knowledge status without provenance details."""

    if not isinstance(payload, dict):
        return None
    mode = str(payload.get("mode") or "").strip().lower()
    if "enabled" in payload:
        enabled = bool(payload.get("enabled"))
    else:
        enabled = bool(mode) and mode != "disabled"
    raw_policy = str(payload.get("policy") or "").strip()
    policy = raw_policy or _default_policy(mode, enabled)

    hints = payload.get("knowledge_hints")
    if isinstance(hints, list):
        hint_count = len(hints)
    elif "hint_count" in payload:
        hint_count = _public_count(payload.get("hint_count"))
    else:
        hint_count = _public_count(payload.get("hit_count"))

    status = str(payload.get("status") or "").strip().lower()
    if status not in _ALLOWED_STATUS:
        status = "pending" if mode and mode != "disabled" else "disabled"
    if mode == "disabled":
        status = "disabled"
        enabled = False
    return {
        "enabled": enabled,
        "status": status,
        "policy": policy,
        "hint_count": hint_count,
    }


def _default_policy(mode: str, enabled: bool) -> str:
    if mode == "disabled":
        return "disabled"
    if mode == "offline":
        return "filtered_context"
    if mode == "enabled":
        return "retrieved_context"
    return "retrieved_context" if enabled else "disabled"


def _public_count(value: Any) -> int:
    if value is None or isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0
