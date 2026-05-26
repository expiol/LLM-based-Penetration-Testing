"""Evidence projections for persistence and seed planning."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from killchain_docker.state.domain import EvidenceRecord

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


@dataclass(frozen=True)
class EvidenceProjection:
    """Derived evidence view for planner seed generation."""

    evidence_id: str
    evidence: object
    output_context: dict[str, object]


class EvidenceProjectionStore:
    """Read-only evidence payload and derived evidence records."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def payload(self) -> dict[str, object]:
        return {
            "evidence": {
                key: value.model_dump(mode="json")
                for key, value in sorted(
                    self.state.evidence.items(), key=lambda item: item[0]
                )
            }
        }

    def records(self) -> list[EvidenceRecord]:
        """Return evidence records in insertion order for prompt projections."""
        return list(self.state.evidence.values())

    def records_by_id(self, evidence_ids: list[str]) -> list[EvidenceRecord]:
        """Return known evidence records matching the requested ids, preserving order."""
        out: list[EvidenceRecord] = []
        for evidence_id in evidence_ids:
            evidence = self.state.evidence.get(evidence_id)
            if evidence is not None:
                out.append(evidence)
        return out

    def existing_refs(self, refs: list[str]) -> list[str]:
        return [ref for ref in refs if ref in self.state.evidence]

    def near_miss_summary(self, *, limit: int = 20) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in self.near_miss_records(limit=limit):
            ctx = item.output_context
            near_misses = list(ctx.get("near_miss_candidates") or [])
            out.append(
                {
                    "evidence_id": item.evidence_id,
                    "tool_name": getattr(item.evidence, "tool_name", ""),
                    "near_miss_candidates": near_misses[:3],
                    "stdout_tail": str(ctx.get("stdout", ""))[-400:],
                }
            )
        return out

    def near_miss_records(
        self, *, limit: int | None = None
    ) -> list[EvidenceProjection]:
        items = list(self.state.evidence.items())
        if limit is not None:
            items = items[-limit:]
        out: list[EvidenceProjection] = []
        for evidence_id, evidence in items:
            ctx = evidence_output_context(evidence)
            if ctx.get("near_miss_candidates"):
                out.append(
                    EvidenceProjection(
                        evidence_id=evidence_id, evidence=evidence, output_context=ctx
                    )
                )
        return out

    def media_scan_records(self) -> list[EvidenceProjection]:
        out: list[EvidenceProjection] = []
        for evidence_id, evidence in self.state.evidence.items():
            if getattr(evidence, "tool_name", None) != "media_scan":
                continue
            ctx = evidence_output_context(evidence)
            if isinstance(ctx.get("media"), list):
                out.append(
                    EvidenceProjection(
                        evidence_id=evidence_id, evidence=evidence, output_context=ctx
                    )
                )
        return out


def evidence_output_context(evidence: object) -> dict[str, object]:
    extracted = getattr(evidence, "extracted", None)
    if not isinstance(extracted, dict):
        return {}
    ctx = extracted.get("output_context")
    return ctx if isinstance(ctx, dict) else {}
