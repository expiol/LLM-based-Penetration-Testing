"""Credential-centric CTF worker."""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.base import (
    build_credential_test_task,
    WorkerAgent,
    build_exploit_hypothesis_task,
    build_flag_validation_task,
    build_path_probe_tasks_for_assets,
    merge_unique_strings,
)
from nyuctf_mutil_killchain.agents.llm_guidance import CredentialHarvestGuidance
from nyuctf_mutil_killchain.prompts import get_worker_system_prompt
from nyuctf_mutil_killchain.state import GlobalState, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ToolExecutionError, ToolExecutionRequest


class CredentialHuntAgent(WorkerAgent):
    """Harvests challenge credentials, tokens, and session material from local artifacts."""

    name = "credential-hunt-agent"
    supported_task_types = ("credential.hunt",)
    routing_summary = "CTF credential harvesting for passwords, tokens, cookies, and login pivots."
    preferred_challenge_categories = ("web", "misc", "forensics", "pwn")

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Credential harvesting requires an execution plane; none is configured.",
                error="CredentialHuntAgent.execution_plane is None",
                retryable=False,
            )

        request = ToolExecutionRequest(
            tool_name="credential_harvest",
            parser_name="jsonl_signals",
            timeout_s=task.input_context.get("timeout_s", 120),
            metadata={
                "files_root": task.input_context.get("files_root", "/home/ctfplayer/ctf_files"),
                "seed_terms": task.input_context.get("seed_terms", []),
                "max_files": task.input_context.get("max_files", 80),
            },
        )
        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary="Credential harvesting execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        output_context = dict(bundle.parsed.output_context)
        credential_candidates = list(output_context.get("credential_candidates") or [])
        credential_ids = [str(item.get("credential_id")) for item in credential_candidates if item.get("credential_id")]
        flag_candidates = list(output_context.get("flag_candidates") or [])
        interesting_paths = list(output_context.get("interesting_paths") or [])
        manual_checks = list(output_context.get("manual_checks") or [])

        challenge_category = str(state.metadata.get("challenge", {}).get("category") or "misc").lower()
        llm_guidance = self.generate_structured_output(
            system_prompt=get_worker_system_prompt(
                challenge_category,
                worker_role=(
                    "You analyze credential-harvesting results and prioritize which "
                    "credentials are most likely to unlock the flag. Determine whether "
                    "to schedule exploit reasoning or credential testing next."
                ),
                evidence_type="credential-harvesting",
                output_schema="CredentialHarvestGuidance",
            ),
            user_prompt=json.dumps(
                {
                    "objective": state.objective,
                    "task_id": task.task_id,
                    "challenge": state.metadata.get("challenge", {}),
                    "summary": bundle.parsed.summary,
                    "credential_candidates": credential_candidates,
                    "known_assets": [
                        {
                            "asset_id": asset.asset_id,
                            "hostname": asset.hostname,
                            "base_url": asset.base_url,
                            "services": [
                                {"port": service.port, "name": service.name, "product": service.product}
                                for service in asset.services
                            ],
                        }
                        for asset in state.assets.values()
                    ],
                    "recent_findings": [
                        {
                            "finding_id": finding.finding_id,
                            "title": finding.title,
                            "severity": finding.severity,
                            "metadata": finding.metadata,
                        }
                        for finding in list(state.findings.values())[-8:]
                    ],
                },
                ensure_ascii=True,
                indent=2,
            ),
            schema=CredentialHarvestGuidance,
        )

        ranking = {
            credential_id: index
            for index, credential_id in enumerate(llm_guidance.prioritized_credential_ids)
            if credential_id
        }
        credential_candidates.sort(key=lambda item: ranking.get(str(item.get("credential_id")), 999))
        flag_candidates = merge_unique_strings(
            flag_candidates,
            llm_guidance.grounded_flag_candidates,
            limit=12,
        )
        interesting_paths = merge_unique_strings(
            interesting_paths,
            llm_guidance.interesting_paths,
            limit=20,
        )
        manual_checks = merge_unique_strings(
            manual_checks,
            llm_guidance.manual_checks,
            limit=8,
        )

        new_tasks = [
            build_flag_validation_task(candidate, source="credential_harvest")
            for candidate in flag_candidates
        ]
        new_tasks.extend(build_path_probe_tasks_for_assets(state, interesting_paths, priority=75))
        if credential_ids:
            for asset in list(state.assets.values())[:4]:
                if not asset.base_url:
                    continue
                new_tasks.append(
                    build_credential_test_task(
                        asset_id=asset.asset_id,
                        base_url=asset.base_url,
                        credential_ids=credential_ids[:6],
                        seed_paths=interesting_paths,
                        priority=84,
                    )
                )

        if credential_candidates and llm_guidance.should_schedule_exploit_hypothesis:
            new_tasks.append(
                build_exploit_hypothesis_task(
                    files_root=str(output_context.get("files_root") or "/home/ctfplayer/ctf_files"),
                    focus_asset_ids=[asset.asset_id for asset in state.assets.values()][:4],
                    seed_terms=[
                        str(candidate.get("username") or "")
                        for candidate in credential_candidates[:6]
                    ],
                    priority=78,
                )
            )

        output_context = {
            **output_context,
            "credential_candidates": credential_candidates,
            "credential_ids": credential_ids,
            "flag_candidates": flag_candidates,
            "interesting_paths": interesting_paths,
            "manual_checks": manual_checks,
        }
        output_context["llm_summary"] = llm_guidance.summary

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=output_context,
            asset_updates=bundle.parsed.asset_updates,
            finding_updates=bundle.parsed.finding_updates,
            credential_updates=bundle.parsed.credential_updates,
            network_updates=bundle.parsed.network_updates,
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + [f"{self.name} harvested credential candidates from challenge artifacts."],
        )
