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

        # The most recent attempt is the most informative. Surface its concrete
        # error fingerprint up front, plus the actual stdout/stderr decoded
        # output so the LLM can SEE what its previous script produced — for
        # crypto/parsing challenges the decoded garbage is usually the
        # smoking gun (e.g. ``Plaintext preview: OHEP{...`` reveals the
        # script mis-parsed a magic byte as part of the key).  Older
        # attempts also carry stdout previews (not just stderr) so the LLM
        # can compare the diverging outputs across approaches.
        last = previous_attempts[-1] or {}
        fingerprint = (last.get("error_fingerprint") or "").strip()
        diagnosis = (last.get("error_diagnosis") or "").strip()
        failure_class = (last.get("failure_class") or "").strip()
        near_miss = list(last.get("near_miss_candidates") or [])
        last_stdout = (last.get("stdout") or "").strip()
        last_stderr = (last.get("stderr") or "").strip()
        last_code = (last.get("solver_code_preview") or "").strip()
        # Occurrence counts come from the cross-chain memory dedup helper
        # (``GlobalState.recent_attempts_for``).  When an entry has been
        # produced N>=3 times, the LLM is stuck in a loop rewriting the
        # same approach — we tell it to PIVOT, not tweak.
        last_occurrences = int(last.get("occurrences") or 1)

        guidance: dict[str, Any] = {}
        if failure_class:
            guidance["failure_class"] = failure_class
        if fingerprint:
            guidance["last_failure_fingerprint"] = fingerprint
            guidance["instruction"] = (
                f"The previous solver attempt failed with: {fingerprint}. "
                "READ the ``last_attempt_stdout`` and ``last_attempt_stderr`` "
                "fields below carefully — they show the EXACT output your "
                "previous script produced.  When the decoded text looks like "
                "garbled flag-shaped tokens (e.g. ``HEP{...`` repeating), the "
                "bug is in header/byte-offset parsing or key derivation, NOT "
                "in your algorithm choice.  Re-read the challenge file with "
                "open() and verify every offset before reusing constants from "
                "the previous attempt."
            )
        # Pivot signal graduated by severity:
        #   1 prior occurrence  → no warning (could be honest first retry)
        #   2 occurrences      → soft pivot prompt
        #   3+ occurrences     → HARD pivot prompt + force diagnostic dump
        if last_occurrences >= 2:
            guidance["last_failure_occurrences"] = last_occurrences
            if last_occurrences >= 3:
                guidance["STOP_REPEATING_THIS_APPROACH"] = (
                    f"You have produced THIS EXACT output {last_occurrences} "
                    "times — you are stuck in a loop.  Your next script MUST "
                    "NOT solve the challenge at all this turn.  INSTEAD, write "
                    "a DIAGNOSTIC script that dumps everything you know about "
                    "the inputs to stderr: raw file bytes (hex), length, "
                    "header parse with every plausible interpretation (little-"
                    "endian vs big-endian, signed vs unsigned, byte vs bit "
                    "positions), expected vs actual outputs of helper functions, "
                    "and intermediate values from your previous solver step-by-"
                    "step.  Print the diagnostic output, then exit 0.  The "
                    "next cycle will use that diagnostic to find the bug."
                )
            else:
                guidance["STOP_REPEATING_THIS_APPROACH"] = (
                    f"You have already produced THIS EXACT output {last_occurrences} "
                    "time(s).  Tweaking constants will NOT work.  Change "
                    "something architectural: for ciphers — swap "
                    "Galois↔Fibonacci, MSB↔LSB, bit-positions↔byte-indices, "
                    "shift direction, indexing base, output byte selection; "
                    "for web — verify the basic GET works and dump the actual "
                    "response headers before assuming the cookie format; for "
                    "binaries — re-read the disassembly carefully.  Pick ONE "
                    "specific architectural change and commit to it."
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

        # CRITICAL: surface the immediately-previous attempt's actual output.
        # Without this the LLM only sees ``fingerprint='exit 0 without flag'``
        # and cannot tell which of its prior approaches was closest.
        if last_stderr:
            guidance["last_attempt_stderr"] = last_stderr[-1200:]
        if last_stdout:
            guidance["last_attempt_stdout"] = last_stdout[-1200:]
        if last_code:
            # Solver_code_preview is already smart-truncated upstream
            # (head + tail), so feeding it through verbatim preserves the
            # parts most likely to harbor the bug.
            guidance["last_attempt_code"] = last_code

        prior_failures: list[dict[str, Any]] = []
        for entry in previous_attempts[:-1]:
            fp = (entry.get("error_fingerprint") or "").strip()
            stderr_tail = (entry.get("stderr") or "").strip()
            stdout_tail = (entry.get("stdout") or "").strip()
            if not fp and not stderr_tail and not stdout_tail:
                continue
            item: dict[str, Any] = {
                "attempt": entry.get("attempt"),
                "fingerprint": fp,
                # ``occurrences`` is the GLOBAL repeat count from cross-chain
                # memory — much more useful than counting within the (already
                # deduped) prior_failures slice.
                "occurrences": int(entry.get("occurrences") or 1),
            }
            if stderr_tail:
                item["stderr_tail"] = stderr_tail[-600:]
            if stdout_tail:
                # Show what the OTHER attempt produced too so the LLM can
                # compare diverging decoded outputs across approaches.
                item["stdout_tail"] = stdout_tail[-400:]
            prior_failures.append(item)
        if prior_failures:
            guidance["prior_failures"] = prior_failures[-4:]
            # Tally fingerprint repeats from two complementary sources:
            #   1. ``occurrences`` field — set by cross-chain dedup
            #      (``GlobalState.recent_attempts_for``), reflects the
            #      GLOBAL repeat count over all of task_type_memory.
            #   2. count within ``prior_failures`` itself — covers the
            #      in-chain retry path where attempts are passed verbatim
            #      and dedup hasn't happened yet.
            local_counts: dict[str, int] = {}
            global_counts: dict[str, int] = {}
            for item in prior_failures:
                fp = (item.get("fingerprint") or "").strip()
                if not fp:
                    continue
                local_counts[fp] = local_counts.get(fp, 0) + 1
                global_counts[fp] = max(
                    global_counts.get(fp, 0),
                    int(item.get("occurrences") or 1),
                )
            repeats = sorted(
                {
                    fp
                    for fp in local_counts
                    if local_counts[fp] >= 2 or global_counts[fp] >= 2
                }
            )
            if repeats:
                # Keep ``repeating_fingerprints`` as a list of strings for
                # the contract callers/tests expect; surface the counts in
                # a sibling dict so the LLM can see HOW MANY times each
                # approach has been rewritten.
                guidance["repeating_fingerprints"] = repeats
                guidance["repeating_fingerprint_counts"] = {
                    fp: max(local_counts.get(fp, 0), global_counts.get(fp, 0))
                    for fp in repeats
                }
                guidance["repeating_note"] = (
                    "Each fingerprint above has already been produced multiple "
                    "times across earlier attempts.  This means the LLM is "
                    "rewriting the SAME approach every cycle and getting the "
                    "SAME garbled output.  STOP iterating on constants and "
                    "PIVOT the algorithm structure (LFSR direction, bit "
                    "ordering, tap interpretation, output byte selection)."
                )

        return guidance or None
