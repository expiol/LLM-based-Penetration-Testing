"""Remove source-identity wording from planner-visible output."""

from __future__ import annotations

import re

from killchain_docker.orchestrator.planning.schemas import PlannedTodo

_SUMMARY_SOURCE_PATTERNS = (
    (re.compile("\\bin\\s+(?:oracle|strict|filtered)\\s+mode\\b", re.IGNORECASE), ""),
    (
        re.compile(
            "\\bthe\\s+related\\s+writeup\\s+for\\s+.+?\\s+is\\s+(?:highly\\s+)?similar\\s*(?:\\([^)]*score[^)]*\\))?\\s+and\\s+",
            re.IGNORECASE,
        ),
        "The technical context ",
    ),
    (re.compile("\\b(?:related\\s+)?writeups?\\b", re.IGNORECASE), "technical context"),
    (
        re.compile(
            "\\bthe\\s+knowledge\\s+hints?\\s+(?:confirm|suggest|indicate)\\b",
            re.IGNORECASE,
        ),
        "The technical evidence suggests",
    ),
    (re.compile("\\bknowledge\\s+hints?\\b", re.IGNORECASE), "technical context"),
    (
        re.compile(
            "\\bRAG[- ]?(?:provided|guided|derived)?\\s*(?:hints?|context|retrieval|results?|sources?)\\b",
            re.IGNORECASE,
        ),
        "technical context",
    ),
    (
        re.compile(
            "\\bretriev(?:al|ed)\\s+(?:hits?|results?|context|sources?|hints?|writeups?|provenance)\\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (
        re.compile("\\bsource identity labels?\\b", re.IGNORECASE),
        "technical provenance",
    ),
    (
        re.compile(
            "\\b(?:similarity\\s+)?score\\s+[-+]?\\d+(?:\\.\\d+)?\\b", re.IGNORECASE
        ),
        "ranking signal",
    ),
    (re.compile("\\bhighly\\s+similar\\b", re.IGNORECASE), "relevant"),
    (
        re.compile(
            "\\b(?:the\\s+)?exact(?:ly)?\\s+(?:same\\s+)?(?:['\\\"][^'\\\"]+['\\\"]\\s+)?(?:[A-Za-z0-9_.-]+\\s+)?challenge(?:\\s+from\\s+[A-Za-z0-9 _.-]+)?",
            re.IGNORECASE,
        ),
        "a closely related challenge",
    ),
    (re.compile("\\bself[- ]?hit\\b", re.IGNORECASE), "technical context"),
    (re.compile("\\boracle\\b", re.IGNORECASE), "supplemental context"),
    (re.compile("\\bstrict\\b", re.IGNORECASE), "filtered"),
    (re.compile("\\bRAG\\b", re.IGNORECASE), "technical context"),
)

_TODO_SOURCE_PATTERNS = (
    (
        re.compile(
            "\\b(?:in|from|under)\\s+(?:oracle|strict|filtered)\\s+mode\\b",
            re.IGNORECASE,
        ),
        "",
    ),
    (
        re.compile(
            "\\bRAG[- ]?(?:provided|guided|derived)?\\s*(?:retrieval\\s+)?(?:hints?|context|hits?|results?|sources?|(?:correct\\s+)?answers?)\\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (
        re.compile(
            "\\b(?:oracle|strict|filtered)[- ]?(?:provided|guided|derived)?\\s*(?:source\\s+identity\\s+labels?|mode|sources?|results?|hints?|context|(?:correct\\s+)?answers?|provenance)\\b",
            re.IGNORECASE,
        ),
        "supplemental context",
    ),
    (
        re.compile(
            "\\bretriev(?:al|ed)\\s+(?:hits?|results?|context|sources?|hints?|writeups?|provenance)\\b",
            re.IGNORECASE,
        ),
        "technical evidence",
    ),
    (
        re.compile("\\bsource identity labels?\\b", re.IGNORECASE),
        "technical provenance",
    ),
    (re.compile("\\bself[- ]?hit\\b", re.IGNORECASE), "technical context"),
    (re.compile("\\bRAG\\b", re.IGNORECASE), "technical context"),
)


def sanitize_planner_decision(decision):
    clean_summary = sanitize_planner_summary(decision.summary)
    clean_notes = [sanitize_planner_summary(note) for note in decision.notes]
    clean_todos = [sanitize_planner_todo(todo) for todo in decision.todos]
    if (
        clean_summary == decision.summary
        and clean_notes == list(decision.notes)
        and clean_todos == list(decision.todos)
    ):
        return decision
    return decision.model_copy(
        update={"summary": clean_summary, "notes": clean_notes, "todos": clean_todos}
    )


def sanitize_planner_summary(summary: str) -> str:
    text = _sanitize_text(summary, _SUMMARY_SOURCE_PATTERNS)
    for bad, good in {
        "provide": "provides",
        "confirm": "confirms",
        "indicate": "indicates",
        "suggest": "suggests",
    }.items():
        text = re.sub(
            f"\\btechnical context {bad}\\b",
            f"technical context {good}",
            text,
            flags=re.IGNORECASE,
        )
    return re.sub("\\s+", " ", text).strip()


def sanitize_planner_todo(todo: PlannedTodo) -> PlannedTodo:
    updates = {
        "goal": _sanitize_text(todo.goal, _TODO_SOURCE_PATTERNS),
        "success_criteria": [
            _sanitize_text(item, _TODO_SOURCE_PATTERNS)
            for item in todo.success_criteria
        ],
        "constraints": [
            _sanitize_text(item, _TODO_SOURCE_PATTERNS) for item in todo.constraints
        ],
    }
    changed = {
        key: value for key, value in updates.items() if value != getattr(todo, key)
    }
    return todo.model_copy(update=changed) if changed else todo


def _sanitize_text(text: str, patterns: tuple[tuple[re.Pattern[str], str], ...]) -> str:
    sanitized = str(text or "").strip()
    for pattern, replacement in patterns:
        sanitized = pattern.sub(replacement, sanitized)
    return re.sub("\\s+", " ", sanitized).strip()
