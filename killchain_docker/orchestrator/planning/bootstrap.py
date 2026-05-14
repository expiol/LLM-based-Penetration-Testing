"""Bootstrap high-level todos for the persona runtime."""

from __future__ import annotations

from killchain_docker.orchestrator.planning.schemas import (
    PlannerAgent,
    PlannedTodo,
    PlannerDecision,
)
from killchain_docker.state import RunState, TodoPhase


class BootstrapSeeder(PlannerAgent):
    """Inject mandatory seed todos for challenge files and authorized scope."""

    def plan(self, state: RunState) -> PlannerDecision:
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        challenge_meta = state.metadata.get("challenge", {}) or {}
        challenge_files = list(challenge_meta.get("files", []) or [])

        if challenge_files and not any(todo.dedupe_key == "bootstrap:artifact-inventory" for todo in state.todos):
            todos.append(
                PlannedTodo(
                    goal="Inventory and classify bundled challenge files.",
                    phase=TodoPhase.RECON,
                    priority=95,
                    context={
                        "files_root": "/home/ctfplayer/ctf_files",
                        "challenge_files": challenge_files,
                    },
                    success_criteria=[
                        "Classify files by kind.",
                        "Surface source, binary, archive, database, pcap, repo, and flag-like evidence.",
                    ],
                    constraints=["Use only files under /home/ctfplayer/ctf_files."],
                    dedupe_key="bootstrap:artifact-inventory",
                )
            )

        for index, scope in enumerate(state.authorized_scope, start=1):
            dedupe_key = f"bootstrap:scope:{scope}"
            if any(todo.dedupe_key == dedupe_key for todo in state.todos):
                continue
            todos.append(
                PlannedTodo(
                    goal=f"Map authorized scope entry {index}.",
                    phase=TodoPhase.RECON,
                    priority=100,
                    context={
                        "scope": scope,
                        "asset_id": "seed-asset" if len(state.authorized_scope) == 1 else f"seed-asset-{index}",
                    },
                    success_criteria=[
                        "Create or update a tracked asset.",
                        "Collect first-pass service or HTTP metadata when possible.",
                    ],
                    constraints=["Stay inside the authorized scope entry."],
                    dedupe_key=dedupe_key,
                )
            )

        if not todos and not state.todos:
            notes.append("No authorized scope or challenge files are available for bootstrap.")
        return PlannerDecision(
            summary=f"Bootstrap proposed {len(todos)} high-level todo(s).",
            todos=todos,
            notes=notes,
        )
