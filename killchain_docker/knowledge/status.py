"""Public and audit-safe RAG Status projections."""

from __future__ import annotations

from typing import Any


def public_rag_payload(payload: object) -> dict[str, Any] | None:
    """Return user-facing RAG Status without retrieval provenance details."""

    if not isinstance(payload, dict):
        return None
    has_enabled = "enabled" in payload
    enabled = bool(payload.get("enabled"))
    mode = str(payload.get("mode") or "").strip().lower()
    policy = {
        "oracle": "supplemental_context",
        "strict": "filtered_context",
        "disabled": "disabled",
    }.get(
        mode,
        str(payload.get("policy") or "").strip()
        or ("supplemental_context" if enabled else "disabled"),
    )
    hints = payload.get("knowledge_hints")
    if isinstance(hints, list):
        hint_count = len(hints)
    elif "hint_count" in payload:
        hint_count = public_count(payload.get("hint_count"))
    else:
        hint_count = public_count(payload.get("hit_count"))
    status = payload.get("status")
    if not status:
        status = "pending" if mode in {"oracle", "strict"} and not has_enabled else "disabled"
        if enabled:
            status = "enabled"
    return {
        "enabled": enabled,
        "status": status,
        "policy": policy,
        "hint_count": hint_count,
    }


def public_count(value: Any) -> int:
    if value is None or isinstance(value, bool):
        return 0
    try:
        return max(0, int(value))
    except (TypeError, ValueError, OverflowError):
        return 0
