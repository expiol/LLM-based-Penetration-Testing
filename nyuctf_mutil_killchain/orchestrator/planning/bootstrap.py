"""Bootstrap seeder.

Seeds the initial task queue when the LLM has no prior state to look at:

- ``artifact.triage`` for any bundled challenge files
- ``recon.enumerate_scope`` for each authorized scope entry

This is the *only* deterministic logic in the planner pipeline.  It exists
because the LLM cannot propose tasks against an empty state - it needs a
starting point.  No filtering or stopping logic lives here.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.orchestrator.planning.schemas import (
    PlannedTask,
    PlannerDecision,
    TaskPlanner,
)
from nyuctf_mutil_killchain.state import GlobalState


class BootstrapSeeder(TaskPlanner):
    """Inject mandatory seed tasks for artifact triage and scope enumeration."""

    def plan(self, state: GlobalState) -> PlannerDecision:
        tasks: list[PlannedTask] = []
        notes: list[str] = []

        challenge_meta = state.metadata.get("challenge", {})
        challenge_files = challenge_meta.get("files", [])

        if challenge_files:
            dedupe_key = "artifact-triage:challenge-files"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is None:
                tasks.append(
                    PlannedTask(
                        title="Inventory challenge files",
                        description=(
                            "Enumerate bundled files in /home/ctfplayer/ctf_files "
                            "and classify interesting artifacts."
                        ),
                        task_type="artifact.triage",
                        priority=95,
                        input_context={
                            "files_root": "/home/ctfplayer/ctf_files",
                            "max_files": 80,
                        },
                        dedupe_key=dedupe_key,
                        metadata={
                            "planned_by": "bootstrap",
                            "challenge_files": challenge_files,
                        },
                    )
                )

        if not state.authorized_scope and not challenge_files:
            notes.append("No authorized scope configured; planner cannot seed recon tasks.")

        for index, scope in enumerate(state.authorized_scope, start=1):
            dedupe_key = f"bootstrap:recon:{scope}"
            if state.task_chain.find_by_dedupe_key(dedupe_key) is None:
                asset_id = (
                    "seed-asset"
                    if len(state.authorized_scope) == 1
                    else f"seed-asset-{index}"
                )
                tasks.append(
                    PlannedTask(
                        title=f"Map authorized surface {index}",
                        description="Normalise a scope entry into a tracked asset with DNS resolution.",
                        task_type="recon.enumerate_scope",
                        priority=100,
                        input_context={"scope": scope, "asset_id": asset_id},
                        dedupe_key=dedupe_key,
                        metadata={"planned_by": "bootstrap"},
                    )
                )

        summary = f"Bootstrap planner proposed {len(tasks)} task(s)."
        return PlannerDecision(summary=summary, tasks=tasks, notes=notes)
