"""Solver prompt rendering.

Pure formatter: takes :class:`SolverEvidence` and produces ``(system_prompt,
user_prompt)`` strings.  No LLM calls or state lookups happen here.
"""

from __future__ import annotations

import json

from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidence
from nyuctf_mutil_killchain.prompts import build_solver_system_prompt


class SolverPromptBuilder:
    """Render solver system + user prompts."""

    def build(self, evidence: SolverEvidence) -> tuple[str, str]:
        category = evidence.category
        timeout = evidence.timeout_s
        system_prompt = build_solver_system_prompt(category, timeout=timeout)

        snapshot = evidence.to_snapshot()

        # Surface near-miss diagnostics prominently if present.
        previous = evidence.previous_attempts
        if previous:
            near_miss_diags: list[str] = []
            for attempt in previous:
                near_miss = attempt.get("near_miss_candidates") or []
                diag = attempt.get("error_diagnosis") or ""
                if near_miss:
                    near_miss_diags.append(
                        f"Attempt {attempt.get('attempt', '?')}: output contained near-miss "
                        f"flag pattern(s) {near_miss} - the decryption produced flag-shaped output "
                        f"but with non-printable/garbage bytes, meaning the key or transform "
                        f"was partially wrong. You MUST use a different strategy for the "
                        f"bytes/positions that produced garbage."
                    )
                elif diag:
                    near_miss_diags.append(diag)
            if near_miss_diags:
                snapshot["CRITICAL_RETRY_GUIDANCE"] = near_miss_diags

        user_prompt = json.dumps(snapshot, ensure_ascii=True, indent=2)
        return system_prompt, user_prompt
