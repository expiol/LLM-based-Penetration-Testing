"""LLM-driven high-level todo proposal."""

from __future__ import annotations

import json
import re

from killchain_docker.knowledge import KnowledgeAugmenter
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.orchestrator.planning.context import PlannerContextBuilder
from killchain_docker.orchestrator.planning.schemas import PlannedTodo, PlannerDecision
from killchain_docker.state import RunState


# Planning contract injected into every planner prompt
_PLANNING_CONTRACT = {
    "output": "Return PlannerDecision with todos, not worker names or tool names.",
    "todo_granularity": "Each todo is a high-level objective with context and success criteria.",
    "todo_phases": "Use exactly one phase per todo: recon, analysis, exploit, or flag_validation.",
    "phase_semantics": (
        "Use flag_validation only for concrete flag candidates already present in state or todo context. "
        "Deriving, decrypting, extracting, or recovering a candidate flag is analysis unless it runs a grounded exploit."
    ),
    "single_phase_batch": (
        "All todos returned in one PlannerDecision must be in the same current phase. "
        "Do not mix recon/analysis/exploit/flag_validation in one batch."
    ),
    "dependency_rule": (
        "If a todo needs information produced by another proposed todo, do not return both. "
        "Return only the upstream todo now and wait for worker results before planning the dependent todo."
    ),
    "exploit_grounding": (
        "Only propose exploit-phase todos without explicit ids when the current state already contains "
        "grounded vulnerabilities, credentials, or sessions. Findings, hypotheses, evidence, and "
        "observed endpoints must be cited in todo context with explicit ids from the current state; "
        "an endpoint may also be cited by a matching base_url or hostname+port from the endpoints list."
    ),
    "stop_rule": "Set stop_run=true only when solved or genuinely exhausted.",
    "no_empty_noop_rule": (
        "If open_todos is 0, the run is unsolved, and stop_run is false, "
        "todos must be non-empty. Returning no todos is only valid with "
        "stop_run=true and a concrete exhaustion reason."
    ),
    "evidence_context_rule": (
        "Use recent_evidence_context as grounded facts from completed tools. "
        "Do not re-request hexdumps, stdout, binary traits, or disassembly snippets "
        "that are already present there; plan the next distinct step from that evidence. "
        "Do not plan work that depends on /tmp files written by an earlier todo. "
        "If raw data is needed, use recent_evidence_context or regenerate and print it in the same script."
    ),
    "evidence_quality_rule": (
        "Treat partial_no_candidate, script_failed, timeout, unbounded_loop_guard, "
        "parse_error, syntax_error, and rejected flag-validation evidence as diagnostic "
        "only. Do not describe an algorithm, key, candidate, or decoded output as confirmed "
        "unless the same evidence includes an explicit successful self-test, a valid flag "
        "candidate, or a validated flag."
    ),
    "scope_boundary_rule": (
        "Keep todos inside authorized_scope and provided challenge files. "
        "Do not pivot to localhost, 127.0.0.1, unrelated local listeners, /root, "
        "/etc, /tmp, /var, /opt, or shell startup files when the authorized remote "
        "service is unavailable. If scope is unreachable and no offline source/file "
        "path remains, produce a blocker diagnostic or set stop_run=true."
    ),
    "novelty_rule": (
        "When stagnation_signals lists a cooled-down family, a new todo in that family "
        "must cite current-state context.evidence_ids or context.hypothesis_id/context.hypothesis_ids "
        "that were not used by previous todos in that family. context.novelty_key may label "
        "the new approach, but it is not grounding by itself. Rephrasing the goal is not novelty."
    ),
}

_SOURCE_IDENTITY_PATTERNS = (
    (
        re.compile(r"\bin\s+(?:oracle|strict|filtered)\s+mode\b", re.IGNORECASE),
        "",
    ),
    (
        re.compile(
            r"\bthe\s+related\s+writeup\s+for\s+.+?\s+is\s+(?:highly\s+)?similar"
            r"\s*(?:\([^)]*score[^)]*\))?\s+and\s+",
            re.IGNORECASE,
        ),
        "The technical context ",
    ),
    (
        re.compile(r"\b(?:related\s+)?writeups?\b", re.IGNORECASE),
        "technical context",
    ),
    (
        re.compile(
            r"\bthe\s+knowledge\s+hints?\s+(?:confirm|suggest|indicate)\b",
            re.IGNORECASE,
        ),
        "The technical evidence suggests",
    ),
    (re.compile(r"\bknowledge\s+hints?\b", re.IGNORECASE), "technical context"),
    (
        re.compile(
            r"\bRAG[- ]?(?:provided|guided|derived)?\s*"
            r"(?:hints?|context|retrieval|results?|sources?)\b",
            re.IGNORECASE,
        ),
        "technical context",
    ),
    (
        re.compile(
            r"\bretriev(?:al|ed)\s+"
            r"(?:hits?|results?|context|sources?|hints?|writeups?|provenance)\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (re.compile(r"\bsource identity labels?\b", re.IGNORECASE), "technical provenance"),
    (
        re.compile(r"\b(?:similarity\s+)?score\s+[-+]?\d+(?:\.\d+)?\b", re.IGNORECASE),
        "ranking signal",
    ),
    (re.compile(r"\bhighly\s+similar\b", re.IGNORECASE), "relevant"),
    (
        re.compile(
            r"\b(?:the\s+)?exact(?:ly)?\s+(?:same\s+)?(?:['\"][^'\"]+['\"]\s+)?"
            r"(?:[A-Za-z0-9_.-]+\s+)?challenge(?:\s+from\s+[A-Za-z0-9 _.-]+)?",
            re.IGNORECASE,
        ),
        "a closely related challenge",
    ),
    (re.compile(r"\bself[- ]?hit\b", re.IGNORECASE), "technical context"),
    (re.compile(r"\boracle\b", re.IGNORECASE), "supplemental context"),
    (re.compile(r"\bstrict\b", re.IGNORECASE), "filtered"),
    (re.compile(r"\bRAG\b", re.IGNORECASE), "technical context"),
)

_TODO_SOURCE_IDENTITY_PATTERNS = (
    (
        re.compile(r"\b(?:in|from|under)\s+(?:oracle|strict|filtered)\s+mode\b", re.IGNORECASE),
        "",
    ),
    (
        re.compile(
            r"\bRAG[- ]?(?:provided|guided|derived)?\s*"
            r"(?:retrieval\s+)?(?:hints?|context|hits?|results?|sources?|(?:correct\s+)?answers?)\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (
        re.compile(
            r"\b(?:oracle|strict|filtered)[- ]?(?:provided|guided|derived)?\s*"
            r"(?:source\s+identity\s+labels?|mode|sources?|results?|hints?|context|"
            r"(?:correct\s+)?answers?|provenance)\b",
            re.IGNORECASE,
        ),
        "supplemental context",
    ),
    (
        re.compile(
            r"\bretriev(?:al|ed)\s+"
            r"(?:hits?|results?|context|sources?|hints?|writeups?|provenance)\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (re.compile(r"\bsource identity labels?\b", re.IGNORECASE), "technical provenance"),
    (re.compile(r"\bself[- ]?hit\b", re.IGNORECASE), "technical context"),
    (re.compile(r"\bRAG\b", re.IGNORECASE), "technical context"),
)


def _sanitize_text(text: str, patterns: tuple[tuple[re.Pattern[str], str], ...]) -> str:
    sanitized = str(text or "").strip()
    for pattern, replacement in patterns:
        sanitized = pattern.sub(replacement, sanitized)
    return re.sub(r"\s+", " ", sanitized).strip()


def sanitize_planner_summary(summary: str) -> str:
    """Remove evaluation/provenance wording from user-facing planner summaries."""
    text = _sanitize_text(summary, _SOURCE_IDENTITY_PATTERNS)
    grammar_fixes = {
        "provide": "provides",
        "confirm": "confirms",
        "indicate": "indicates",
        "suggest": "suggests",
    }
    for bad, good in grammar_fixes.items():
        text = re.sub(
            rf"\btechnical context {bad}\b",
            f"technical context {good}",
            text,
            flags=re.IGNORECASE,
        )
    return re.sub(r"\s+", " ", text).strip()


def sanitize_planner_todo(todo: PlannedTodo) -> PlannedTodo:
    """Remove provenance wording from todo text without changing domain terms."""
    goal = _sanitize_text(todo.goal, _TODO_SOURCE_IDENTITY_PATTERNS)
    success_criteria = [
        _sanitize_text(item, _TODO_SOURCE_IDENTITY_PATTERNS)
        for item in todo.success_criteria
    ]
    constraints = [
        _sanitize_text(item, _TODO_SOURCE_IDENTITY_PATTERNS)
        for item in todo.constraints
    ]
    updates = {
        key: value
        for key, value in {
            "goal": goal,
            "success_criteria": success_criteria,
            "constraints": constraints,
        }.items()
        if value != getattr(todo, key)
    }
    return todo.model_copy(update=updates) if updates else todo


class PlanStrategy:
    """Submit the current run state to the LLM and return high-level todos."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        augmenter: KnowledgeAugmenter | None = None,
    ) -> None:
        if llm_client is None:
            raise LLMClientError("PlanStrategy requires an LLM client.")
        self.llm_client = llm_client
        self.context_builder = PlannerContextBuilder(augmenter=augmenter)

    def propose(
        self,
        state: RunState,
        *,
        require_action: bool = False,
        previous_summary: str | None = None,
    ) -> PlannerDecision:
        ctx = self.context_builder.build(state)
        decision = self.llm_client.generate_json(
            system_prompt=self.context_builder.system_prompt(state),
            user_prompt=self._render_prompt(
                ctx,
                require_action=require_action,
                previous_summary=previous_summary,
            ),
            schema=PlannerDecision,
            temperature=ctx.temperature,
        )
        clean_summary = sanitize_planner_summary(decision.summary)
        clean_notes = [sanitize_planner_summary(note) for note in decision.notes]
        clean_todos = [sanitize_planner_todo(todo) for todo in decision.todos]
        if (
            clean_summary != decision.summary
            or clean_notes != list(decision.notes)
            or clean_todos != list(decision.todos)
        ):
            return decision.model_copy(
                update={"summary": clean_summary, "notes": clean_notes, "todos": clean_todos}
            )
        return decision

    @staticmethod
    def _render_prompt(
        ctx,
        *,
        require_action: bool = False,
        previous_summary: str | None = None,
    ) -> str:
        """Render PlannerContext into the JSON prompt string for the LLM."""
        snapshot = {
            "objective": ctx.objective,
            "authorized_scope": ctx.authorized_scope,
            "challenge_category": ctx.challenge_category,
            "planning_profiles": ctx.planning_profiles,
            "summary": ctx.state_summary,
            "assets": ctx.assets,
            "artifacts": ctx.artifacts,
            "endpoints": ctx.endpoints,
            "findings": ctx.findings,
            "flag_candidates": ctx.flag_candidates,
            "rejected_flag_candidates": ctx.rejected_flag_candidates,
            "todos": ctx.todos,
            "recent_round_summaries": ctx.recent_round_summaries,
            "recent_evidence_context": ctx.recent_evidence_context,
            "recent_execution_log": ctx.recent_execution_log,
            "stagnation_signals": ctx.stagnation,
            "near_miss_evidence": ctx.near_miss_evidence,
            "working_memory": ctx.working_memory,
            "knowledge_augmentation": ctx.knowledge_augmentation,
        }
        if ctx.pivot_summaries:
            snapshot["pivot_required"] = ctx.pivot_summaries
        snapshot["planning_contract"] = {
            **_PLANNING_CONTRACT,
            "open_todos": ctx.open_todo_count,
        }
        if require_action:
            snapshot["planner_retry_instruction"] = {
                "reason": "previous planner response returned no actionable todos without stop_run=true",
                "previous_summary": str(previous_summary or "")[:400],
                "required_response": (
                    "Return at least one grounded next todo that cites current state evidence, "
                    "or set stop_run=true with a concise exhaustion reason."
                ),
            }
        return json.dumps(snapshot, ensure_ascii=True, indent=2)
