"""LLM-driven task proposal.

Calls the LLM with the current state snapshot and asks it to return a
:class:`PlannerDecision`.  No filtering, no whitelist, no phase-guidance.
The LLM owns task selection and stop_run.
"""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.orchestrator.planning.schemas import PlannerDecision
from nyuctf_mutil_killchain.prompts import (
    get_analysis_strategy,
    get_exploit_strategy,
    get_planner_system_prompt,
    get_prompts,
)
from nyuctf_mutil_killchain.state import GlobalState


class PlanStrategy:
    """Submit the current state to the LLM and return a raw PlannerDecision."""

    def __init__(self, llm_client: LLMClient) -> None:
        if llm_client is None:
            raise LLMClientError("PlanStrategy requires an LLM client.")
        self.llm_client = llm_client

    def propose(self, state: GlobalState) -> PlannerDecision:
        return self.llm_client.generate_json(
            system_prompt=self._system_prompt(state),
            user_prompt=self._user_prompt(state),
            schema=PlannerDecision,
        )

    def _system_prompt(self, state: GlobalState) -> str:
        category = self._category(state)
        return get_planner_system_prompt(category)

    # Tunable bounds for the planner prompt.  The previous implementation
    # serialized every finding and every task ever queued, which on long runs
    # ballooned the prompt to >50 KB per cycle and added measurable LLM latency.
    # These bounds keep the prompt under ~12 KB while still giving the planner
    # the most actionable signals (recent failures + open tasks + key findings).
    _MAX_FINDINGS = 24
    _MAX_FINDING_DESCRIPTION_CHARS = 280
    _MAX_FINDING_METADATA_CHARS = 240
    _MAX_TASK_HISTORY = 60

    def _user_prompt(self, state: GlobalState) -> str:
        category = self._category(state)
        prompts = get_prompts(category)
        snapshot = {
            "objective": state.objective,
            "authorized_scope": state.authorized_scope,
            "challenge_category": category,
            "analysis_strategy": prompts.analysis_strategy,
            "exploit_strategy": prompts.exploit_strategy,
            "flag_recovery_hints": prompts.flag_recovery_hints,
            "summary": state.summary(),
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "kind": asset.kind,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "base_url": asset.base_url,
                    "services": [
                        {
                            "port": s.port,
                            "name": s.name,
                            "product": s.product,
                            "version": s.version,
                        }
                        for s in asset.services
                    ],
                    "tags": sorted(asset.tags),
                }
                for asset in state.assets.values()
            ],
            "findings": self._serialize_findings(state),
            "credentials": [
                {
                    "credential_id": cred.credential_id,
                    "username": cred.username,
                    "credential_type": cred.credential_type,
                    "asset_ref": cred.asset_ref,
                }
                for cred in list(state.credentials.values())[-8:]
            ],
            "task_history": self._serialize_task_history(state),
            "recent_execution_log": self._collect_execution_log(state),
        }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)

    def _serialize_findings(self, state: GlobalState) -> list[dict[str, object]]:
        """Cap findings at a reasonable size and trim long preview strings.

        Prefer the most recent findings: the LLM doesn't need a 200-finding
        backlog from earlier cycles to plan the next move.
        """
        findings = list(state.findings.values())[-self._MAX_FINDINGS:]
        result: list[dict[str, object]] = []
        for finding in findings:
            metadata_preview = {}
            for key in (
                "stdout_preview", "source_snippet", "key_observations",
                "interesting_routes", "interesting_paths", "flag_candidates",
                "near_miss_candidates", "function_inventory", "archive_members",
            ):
                value = finding.metadata.get(key)
                if not value:
                    continue
                metadata_preview[key] = str(value)[:self._MAX_FINDING_METADATA_CHARS]
            result.append({
                "finding_id": finding.finding_id,
                "title": finding.title,
                "severity": finding.severity,
                "description": (finding.description or "")[:self._MAX_FINDING_DESCRIPTION_CHARS],
                "asset_refs": finding.asset_refs,
                "evidence_refs": finding.evidence_refs[:6],
                "metadata_preview": metadata_preview,
            })
        return result

    def _serialize_task_history(self, state: GlobalState) -> list[dict[str, object]]:
        """Show the most recent tasks plus every still-open task.

        Long-running runs accumulate hundreds of tasks; sending them all every
        cycle costs LLM tokens without giving the planner extra signal.  We
        always include open tasks (PENDING/RUNNING/BLOCKED) so the planner can
        avoid duplicating in-flight work, plus the tail of the queue for
        recent context.
        """
        from nyuctf_mutil_killchain.state import TaskStatus

        all_tasks = state.task_chain.tasks
        seen_ids: set[str] = set()
        ordered: list = []
        # Open tasks first (they always matter regardless of recency).
        for task in all_tasks:
            if task.status in {TaskStatus.PENDING, TaskStatus.RUNNING, TaskStatus.BLOCKED}:
                seen_ids.add(task.task_id)
                ordered.append(task)
        # Then the tail of recently completed/failed tasks for context.
        for task in reversed(all_tasks):
            if task.task_id in seen_ids:
                continue
            seen_ids.add(task.task_id)
            ordered.append(task)
            if len(ordered) >= self._MAX_TASK_HISTORY:
                break

        return [
            {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "status": task.status,
                "title": task.title,
                "dedupe_key": task.dedupe_key,
                "last_error": (task.last_error or "")[:200] or None,
                "error_code": task.error_code,
            }
            for task in ordered
        ]

    @staticmethod
    def _collect_execution_log(state: GlobalState) -> list[dict[str, object]]:
        """Recent execution log for the planner.

        Takes the last 24 records and overlays every recent failure that fell
        outside the window — even when the cycle budget gets spent quickly,
        the planner still sees *why* past attempts failed instead of replanning
        the same dead-end task type.
        """
        recent = list(state.execution_log[-24:])
        seen_ids = {record.task_id for record in recent}
        recent_failures: list = []
        for record in reversed(state.execution_log[:-24] if len(state.execution_log) > 24 else []):
            if record.success:
                continue
            if record.task_id in seen_ids:
                continue
            recent_failures.append(record)
            seen_ids.add(record.task_id)
            if len(recent_failures) >= 12:
                break
        for record in reversed(recent_failures):
            recent.insert(0, record)
        return [
            {
                "task_id": record.task_id,
                "worker_name": record.worker_name,
                "success": record.success,
                "summary": record.summary,
                "error": record.error,
            }
            for record in recent
        ]

    @staticmethod
    def _category(state: GlobalState) -> str:
        return str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
