"""Solver prompt rendering.

Pure formatter: takes :class:`SolverEvidence` and produces ``(system_prompt,
user_prompt)`` strings.  No LLM calls or state lookups happen here.

When the evidence carries ``previous_attempts`` (i.e. this is a retry), we
surface the concrete failure fingerprint and offending source line at the top
of the user prompt so the LLM corrects the specific bug instead of restarting
from scratch.
"""

from __future__ import annotations

import json
from typing import Any

from nyuctf_mutil_killchain.agents.solver.evidence import SolverEvidence
from nyuctf_mutil_killchain.prompts import build_solver_system_prompt


class SolverPromptBuilder:
    """Render solver system + user prompts."""

    def build(self, evidence: SolverEvidence) -> tuple[str, str]:
        category = evidence.category
        timeout = evidence.timeout_s
        system_prompt = build_solver_system_prompt(category, timeout=timeout)

        snapshot = evidence.to_snapshot()

        retry_block = self._build_retry_block(evidence.previous_attempts)
        if retry_block is not None:
            snapshot["CRITICAL_RETRY_GUIDANCE"] = retry_block

        user_prompt = json.dumps(snapshot, ensure_ascii=True, indent=2)
        return system_prompt, user_prompt

    @staticmethod
    def _build_retry_block(previous_attempts: list[dict[str, Any]]) -> dict[str, Any] | None:
        if not previous_attempts:
            return None

        # The most recent attempt is the most informative.  Surface its concrete
        # error fingerprint up front; carry older attempt summaries below.
        last = previous_attempts[-1] or {}
        fingerprint = (last.get("error_fingerprint") or "").strip()
        diagnosis = (last.get("error_diagnosis") or "").strip()
        near_miss = list(last.get("near_miss_candidates") or [])

        guidance: dict[str, Any] = {}
        if fingerprint:
            guidance["last_failure_fingerprint"] = fingerprint
            guidance["instruction"] = (
                f"The previous solver attempt failed with: {fingerprint}. "
                "Your new script MUST avoid this exact failure. Read the relevant "
                "challenge file(s) before reusing any constant or path. Do NOT "
                "repeat the previous algorithmic approach when the failure was "
                "logical (wrong header offset, wrong key length, etc.) — pick a "
                "fundamentally different decoding/parsing strategy."
            )
        if diagnosis:
            guidance["diagnosis"] = diagnosis
        if near_miss:
            guidance["near_miss_examples"] = near_miss[:3]
            guidance["near_miss_note"] = (
                "Earlier output produced flag-shaped tokens with garbled bytes. "
                "Refine the transform so the body is fully printable ASCII; do not "
                "post-process garbage characters away — fix the underlying logic."
            )

        prior_failures = [
            {
                "attempt": entry.get("attempt"),
                "fingerprint": entry.get("error_fingerprint"),
            }
            for entry in previous_attempts[:-1]
            if entry.get("error_fingerprint")
        ]
        if prior_failures:
            guidance["prior_failures"] = prior_failures[-4:]

        return guidance or None
