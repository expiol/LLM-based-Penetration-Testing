"""Deterministic task-intent predicates for worker execution."""

from __future__ import annotations
import re
from killchain_docker.orchestrator.goal_predicates import (
    goal_requires_artifact_extraction,
)
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.todos import TodoItem


def is_flag_recovery_task(todo: TodoItem) -> bool:
    text = " ".join(
        [todo.goal, " ".join(todo.success_criteria), " ".join(todo.constraints)]
    ).lower()
    if "flag candidate" in text or "candidate flag" in text:
        return True
    if "flag format" in text or "flag pattern" in text:
        return True
    if re.search(
        "\\b(recover|derive|find|print|extract|decrypt|decode)\\s+(?:the\\s+)?flag\\b",
        text,
    ):
        return True
    if any(
        (token in text for token in ("recover", "decrypt", "decode", "print", "output"))
    ):
        if "plaintext" in text or "readable ascii" in text:
            return True
    if "output contains" in text and ("flag{" in text or "ctf{" in text):
        return True
    return False


def is_execution_closure_task(todo: TodoItem) -> bool:
    """Return true for tasks expected to close artifact-to-answer gaps."""
    intent = DispatchIntent.from_context(todo.context)
    if intent.profile == "execution_closure":
        return True
    if is_flag_recovery_task(todo):
        return True
    if is_analysis_only_task(todo, intent):
        return False
    text = " ".join(
        [todo.goal, " ".join(todo.success_criteria), " ".join(todo.constraints)]
    ).lower()
    action_terms = (
        "carve",
        "decode",
        "decrypt",
        "derive",
        "extract",
        "find",
        "inspect",
        "parse",
        "print",
        "read",
        "recover",
        "reconstruct",
        "search",
    )
    target_terms = (
        "artifact",
        "barcode",
        "embedded",
        "file",
        "flag",
        "hidden",
        "image",
        "jpg",
        "jpeg",
        "key",
        "password",
        "plaintext",
        "png",
        "qr",
        "secret",
        "stego",
        "token",
        "transferred file",
    )
    return contains_any_term(text, action_terms) and contains_any_term(
        text, target_terms
    )


def is_analysis_only_task(todo: TodoItem, intent: DispatchIntent) -> bool:
    context = todo.context or {}
    family = str(context.get("family") or "").strip().lower()
    profile = str(intent.profile or "").strip().lower()
    if family in {"source-review", "artifact-inventory", "artifact-followup"}:
        return True
    if profile in {"artifact_analysis", "binary_analysis", "media_inspection"}:
        return True
    text = " ".join(
        [todo.goal, " ".join(todo.success_criteria), " ".join(todo.constraints)]
    ).lower()
    analysis_terms = (
        "analyze",
        "classify",
        "determine",
        "document",
        "identify",
        "inventory",
        "locate",
        "map",
        "summarize",
        "understand",
    )
    closure_outcome_terms = (
        "candidate",
        "flag",
        "hidden",
        "payload",
        "recover",
        "recovered",
    )
    return contains_any_term(text, analysis_terms) and (
        not contains_any_term(text, closure_outcome_terms)
    )


def artifact_triage_intent_is_direct(task: TodoItem) -> bool:
    context = task.context or {}
    family = str(context.get("family") or "").strip()
    text = " ".join(
        [task.goal, " ".join(task.success_criteria), " ".join(task.constraints)]
    ).lower()
    if family == "artifact-inventory":
        return not goal_requires_artifact_extraction(text)
    if family != "artifact-followup":
        return False
    if goal_requires_artifact_extraction(text):
        return False
    return any(
        (
            token in text
            for token in (
                "artifact follow-up",
                "classify",
                "deterministic",
                "first-pass",
                "inspect",
                "inventory",
                "scan",
                "triage",
            )
        )
    )


def contains_any_term(text: str, terms: tuple[str, ...]) -> bool:
    for term in terms:
        if re.search(f"(?<![A-Za-z0-9_]){re.escape(term)}(?![A-Za-z0-9_])", text):
            return True
    return False
