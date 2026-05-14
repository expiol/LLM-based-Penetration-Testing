"""Planner-facing run-memory updates."""

from __future__ import annotations

import json

from pydantic import BaseModel, Field

from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.state import GlobalState, RunMemory, WorkerReport
from killchain_docker.state.models import utc_now


class MemoryUpdate(BaseModel):
    """LLM-produced replacement for bounded run memory."""

    long_term_summary: str = ""
    confirmed_facts: list[str] = Field(default_factory=list)
    open_questions: list[str] = Field(default_factory=list)
    dead_ends: list[str] = Field(default_factory=list)
    current_focus: str = ""


class LLMMemoryUpdater:
    """Fold fresh worker evidence into planner-facing long-term memory."""

    _MAX_LIST_ITEMS = 40
    _MAX_SUMMARY_CHARS = 3000

    def __init__(self, llm_client: LLMClient) -> None:
        if llm_client is None:
            raise LLMClientError("LLMMemoryUpdater requires an LLM client.")
        self.llm_client = llm_client

    def update(self, state: GlobalState, report: WorkerReport) -> RunMemory:
        snapshot = {
            "previous_memory": state.run_memory.model_dump(mode="json"),
            "worker_report": {
                "task_id": report.task_id,
                "worker_name": report.worker_name,
                "success": report.success,
                "summary": report.summary,
                "error": report.error,
                "output_context": self._trim_mapping(report.output_context),
                "notes": report.notes[-8:],
                "planner_signals": [
                    signal.model_dump(mode="json")
                    for signal in report.planner_signals[-8:]
                ],
            },
            "state_summary": state.summary(),
            "recent_execution_log": [
                record.model_dump(mode="json")
                for record in state.execution_log[-12:]
            ],
            "recent_planner_signals": [
                signal.model_dump(mode="json")
                for signal in state.planner_signals[-12:]
            ],
        }
        update = self.llm_client.generate_json(
            system_prompt=(
                "Update bounded run memory for a planner-first penetration "
                "testing workflow. Preserve confirmed facts, open questions, "
                "dead ends, and the current focus. Be concise. Return only JSON "
                "matching MemoryUpdate."
            ),
            user_prompt=json.dumps(snapshot, ensure_ascii=True, indent=2),
            schema=MemoryUpdate,
            temperature=0.1,
        )
        memory = RunMemory(
            long_term_summary=update.long_term_summary[: self._MAX_SUMMARY_CHARS],
            confirmed_facts=update.confirmed_facts[-self._MAX_LIST_ITEMS :],
            open_questions=update.open_questions[-self._MAX_LIST_ITEMS :],
            dead_ends=update.dead_ends[-self._MAX_LIST_ITEMS :],
            current_focus=update.current_focus[:500],
            last_updated_at=utc_now(),
        )
        state.run_memory = memory
        state.touch()
        return memory

    @staticmethod
    def _trim_mapping(value: dict[str, object]) -> dict[str, object]:
        trimmed: dict[str, object] = {}
        for key, item in value.items():
            text = str(item)
            trimmed[key] = text[:1000] if len(text) > 1000 else item
        return trimmed


__all__ = ["LLMMemoryUpdater", "MemoryUpdate"]
