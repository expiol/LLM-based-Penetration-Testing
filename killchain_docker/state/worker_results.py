"""Worker-result application policy."""

from __future__ import annotations
from typing import TYPE_CHECKING
from killchain_docker.state.evidence_facts import EvidenceFactStore
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.maintenance import RunStateMaintenance
from killchain_docker.memory.store import RunMemoryStore
from killchain_docker.state.recon_facts import ReconFactStore
from killchain_docker.state.domain import StateDelta
from killchain_docker.state.todos import TodoItem, WorkerResult
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.state_delta import StateDeltaApplier

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class WorkerResultApplier:
    """Applies one worker result to todos, facts, memory, outcome, and journal."""

    def __init__(self, state: "RunState") -> None:
        self.state = state
        self.recon_facts = ReconFactStore(state)
        self.evidence_facts = EvidenceFactStore(state)
        self.journal = RunJournal(state)
        self.maintenance = RunStateMaintenance(state)
        self.memory = RunMemoryStore(state.run_memory)
        self.outcome = RunOutcomeStore(state)
        self.delta_applier = StateDeltaApplier(state)

    def apply(self, result: WorkerResult) -> None:
        from killchain_docker.orchestrator.todo.queue import TodoQueue

        todos = TodoQueue(self.state)
        todo = todos.get(result.todo_id)
        if todo is None:
            raise KeyError(f"Unknown todo id: {result.todo_id}")
        record_todo_execution_context(todo, result)
        if failed_result_has_diagnostic_signal(result):
            result.partial = True
            result.partial_reason = (
                result.partial_reason
                or result.error
                or result.summary
                or "tool failed after producing diagnostic evidence"
            )
            result.result_quality = result.result_quality or "diagnostic_evidence"
            result.output_context.setdefault("result_quality", result.result_quality)
            result.output_context.setdefault("partial_reason", result.partial_reason)
        todos.apply_result(todo, result, touch=False)
        for asset in result.asset_updates:
            self.recon_facts.asset(asset)
        for finding in result.finding_updates:
            self.recon_facts.finding(finding)
        for credential in result.credential_updates:
            self.recon_facts.credential(credential)
        for evidence in result.evidence_updates:
            self.evidence_facts.evidence(evidence)
        self.recon_facts.network_edges(result.network_updates)
        annotate_result_artifacts(result)
        self.delta_applier.apply(result.state_delta)
        if result.memory_updates:
            self.memory.upsert_many(result.memory_updates)
        if result.solved:
            self.outcome.solved(
                validated_flag=result.validated_flag,
                reason="worker_validated_flag"
                if result.validated_flag
                else "worker_solved",
                touch=False,
            )
        if result.validated_flag:
            self.outcome.validated_flag(result.validated_flag, touch=False)
        self.journal.worker_execution(result, touch=False)
        self.journal.notes(result.notes, touch=False)
        self.maintenance.touch()


_NON_DIAGNOSTIC_FAILURE_QUALITIES = frozenset(
    {
        "infrastructure_error",
        "llm_error",
        "llm_schema_validation",
        "metadata_validation",
        "scope_violation_blocked",
    }
)


def failed_result_has_diagnostic_signal(result: WorkerResult) -> bool:
    """Return true when a failed result still produced useful evidence."""
    if result.success or result.partial or result.retryable:
        return False
    quality = str(
        result.result_quality or result.output_context.get("failure_kind") or ""
    ).strip()
    if quality in _NON_DIAGNOSTIC_FAILURE_QUALITIES:
        return False
    if state_delta_has_signal(result.state_delta):
        return True
    if (
        result.asset_updates
        or result.finding_updates
        or result.credential_updates
        or result.network_updates
    ):
        return True
    ctx = result.output_context or {}
    if ctx.get("flag_candidates") or ctx.get("near_miss_candidates"):
        return True
    if payload_has_observation(ctx):
        return True
    for evidence in result.evidence_updates:
        if payload_has_observation(evidence.result):
            return True
        extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
        if payload_has_observation(extracted):
            return True
        evidence_ctx = extracted.get("output_context")
        if payload_has_observation(evidence_ctx):
            return True
    return False


def state_delta_has_signal(delta: StateDelta | None) -> bool:
    if delta is None:
        return False
    return bool(
        delta.artifacts
        or delta.endpoints
        or delta.routes
        or delta.flag_candidates
        or delta.hypotheses
        or delta.vulnerabilities
        or delta.exploit_attempts
        or delta.sessions
    )


def payload_has_observation(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in (
        "stdout",
        "stderr",
        "output_text",
        "raw_log",
        "stdout_preview",
        "stderr_preview",
    ):
        if str(payload.get(key) or "").strip():
            return True
    return False


def annotate_result_artifacts(result: WorkerResult) -> None:
    evidence_ids = [
        evidence.evidence_id
        for evidence in result.evidence_updates
        if getattr(evidence, "evidence_id", "")
    ]
    capability = str(result.output_context.get("capability") or "").strip()
    for artifact in result.state_delta.artifacts:
        if evidence_ids:
            existing = artifact.metadata.get("evidence_ids")
            if isinstance(existing, list):
                merged = [str(item) for item in existing if str(item).strip()]
            else:
                merged = []
            for evidence_id in evidence_ids:
                if evidence_id not in merged:
                    merged.append(evidence_id)
            artifact.metadata["evidence_ids"] = merged
        artifact.metadata.setdefault("source_task_id", result.todo_id)
        artifact.metadata.setdefault("source_worker", result.worker_name)
        if capability:
            artifact.metadata.setdefault("source_capability", capability)


def record_todo_execution_context(todo: TodoItem, result: WorkerResult) -> None:
    ctx = result.output_context if isinstance(result.output_context, dict) else {}
    capability = str(ctx.get("capability") or "").strip()
    if capability:
        todo.context.setdefault("executed_capability", capability)
    for key in ("path", "artifact_path", "file_path"):
        value = str(ctx.get(key) or "").strip()
        if value:
            todo.context.setdefault("executed_path", value)
            break
    paths = ctx.get("paths")
    if isinstance(paths, list):
        clean_paths = [str(item).strip() for item in paths if str(item).strip()]
        if clean_paths:
            todo.context.setdefault("executed_paths", clean_paths)
