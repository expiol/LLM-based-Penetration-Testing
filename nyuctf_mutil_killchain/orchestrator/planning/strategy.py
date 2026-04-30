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
            "findings": [
                {
                    "finding_id": finding.finding_id,
                    "title": finding.title,
                    "severity": finding.severity,
                    "description": finding.description,
                    "asset_refs": finding.asset_refs,
                    "evidence_refs": finding.evidence_refs,
                    "metadata_preview": {
                        k: str(v)[:400]
                        for k, v in finding.metadata.items()
                        if k in {
                            "stdout_preview", "source_snippet", "key_observations",
                            "interesting_routes", "interesting_paths", "flag_candidates",
                            "near_miss_candidates", "function_inventory", "archive_members",
                        }
                        and v
                    },
                }
                for finding in state.findings.values()
            ],
            "credentials": [
                {
                    "credential_id": cred.credential_id,
                    "username": cred.username,
                    "credential_type": cred.credential_type,
                    "asset_ref": cred.asset_ref,
                }
                for cred in list(state.credentials.values())[-8:]
            ],
            "task_history": [
                {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status,
                    "title": task.title,
                    "dedupe_key": task.dedupe_key,
                }
                for task in state.task_chain.tasks
            ],
            "recent_execution_log": [
                {
                    "task_id": record.task_id,
                    "worker_name": record.worker_name,
                    "success": record.success,
                    "summary": record.summary,
                    "error": record.error,
                }
                for record in state.execution_log[-8:]
            ],
        }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)

    @staticmethod
    def _category(state: GlobalState) -> str:
        return str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
