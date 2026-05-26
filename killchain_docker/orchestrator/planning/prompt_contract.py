"""Prompt contract injected into planner LLM requests."""

from __future__ import annotations

PLANNING_CONTRACT = {
    "output": "Return PlannerDecision with todos, not worker names or tool names.",
    "todo_granularity": "Each todo is a high-level objective with context and success criteria.",
    "todo_phases": "Use exactly one phase per todo: recon, analysis, exploit, or flag_validation.",
    "phase_semantics": "Use flag_validation only for concrete flag candidates already present in state or todo context. Deriving, decrypting, extracting, or recovering a candidate flag is analysis unless it runs a grounded exploit.",
    "single_phase_batch": "All todos returned in one PlannerDecision must be in the same current phase. Do not mix recon/analysis/exploit/flag_validation in one batch.",
    "dependency_rule": "If a todo needs information produced by another proposed todo, do not return both. Return only the upstream todo now and wait for worker results before planning the dependent todo. When a todo depends on an already queued/current-state todo, set depends_on to that todo's todo_id or dedupe_key; the dispatcher will hold it until dependencies complete.",
    "exploit_grounding": "Only propose exploit-phase todos without explicit ids when the current state already contains grounded vulnerabilities, credentials, or sessions. Findings, hypotheses, evidence, and observed endpoints must be cited in todo context with explicit ids from the current state; an endpoint may also be cited by a matching base_url or hostname+port from the endpoints list.",
    "stop_rule": "Set stop_run=true only when solved or genuinely exhausted.",
    "no_empty_noop_rule": "If open_todos is 0, the run is unsolved, and stop_run is false, todos must be non-empty. Returning no todos is only valid with stop_run=true and a concrete exhaustion reason.",
    "evidence_context_rule": "Use recent_evidence_context as grounded facts from completed tools. Do not re-request hexdumps, stdout, binary traits, or disassembly snippets that are already present there; plan the next distinct step from that evidence. Do not plan work that depends on /tmp files written by an earlier todo. If raw data is needed, use recent_evidence_context or regenerate and print it in the same script.",
    "evidence_quality_rule": "Treat partial_no_candidate, script_failed, timeout, unbounded_loop_guard, parse_error, syntax_error, and rejected flag-validation evidence as diagnostic only. Do not describe an algorithm, key, candidate, or decoded output as confirmed unless the same evidence includes an explicit successful self-test, a valid flag candidate, or a validated flag.",
    "scope_boundary_rule": "Keep todos inside authorized_scope and provided challenge files. Do not pivot to localhost, 127.0.0.1, unrelated local listeners, /root, /etc, /tmp, /var, /opt, or shell startup files when the authorized remote service is unavailable. If scope is unreachable and no offline source/file path remains, produce a blocker diagnostic or set stop_run=true.",
    "novelty_rule": "When stagnation_signals lists a cooled-down family, a new todo in that family must cite current-state context.evidence_ids or context.hypothesis_id/context.hypothesis_ids that were not used by previous todos in that family. context.novelty_key may label the new approach, but it is not grounding by itself. Rephrasing the goal is not novelty.",
}
