"""Normalize planned todos that should execute solver-style closure work."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from killchain_docker.orchestrator.goal_predicates import (
    goal_requires_executable_interaction,
)
from killchain_docker.orchestrator.todo_dispatch_intent import set_required_capability
from killchain_docker.state.todos import TodoPhase

if TYPE_CHECKING:
    from killchain_docker.orchestrator.planning.schemas import PlannedTodo


def apply_execution_closure_context(
    todo: "PlannedTodo", context: dict[str, object], family: str
) -> None:
    if todo.phase not in {TodoPhase.ANALYSIS, TodoPhase.EXPLOIT}:
        return
    if family not in {
        "algorithm-verification",
        "binary-dynamic",
        "binary-static",
        "crypto-decrypt",
        "flag-recovery",
        "binary-analysis",
        "pwn-exploit",
        "web-exploitation",
    }:
        return
    text = " ".join(
        [
            todo.goal,
            " ".join((str(item) for item in todo.success_criteria)),
            " ".join((str(item) for item in todo.constraints)),
        ]
    ).lower()
    if analysis_only_closure_exempt(text):
        return
    if not has_execution_closure_intent(text, todo.phase):
        return
    profile = "execution_closure"
    if todo.phase == TodoPhase.EXPLOIT and family == "pwn-exploit":
        profile = "pwn_exploit"
    elif todo.phase == TodoPhase.EXPLOIT and family == "web-exploitation":
        profile = "web_exploitation"
    set_required_capability(context, profile=profile, capability="script.exec")


def analysis_only_closure_exempt(text: str) -> bool:
    if has_concrete_recovery_outcome(text):
        return False
    return bool(
        re.search(
            "\\b(analy[sz]e|analysis|audit|classify|document|examine|explain|identify|inspect|inventory|locate|map|review|summari[sz]e|understand)\\b",
            text,
        )
    )


def has_execution_closure_intent(text: str, phase: TodoPhase) -> bool:
    if has_concrete_recovery_outcome(text):
        return True
    if phase == TodoPhase.EXPLOIT and goal_requires_executable_interaction(text):
        return True
    return bool(
        re.search(
            "\\b(apply|build|compare|execute|implement|run|validate|verify)\\b", text
        )
        and re.search(
            "\\b(algorithm|cipher|decode|decrypt|encoded|reference|solver|transform)\\b",
            text,
        )
    )


def has_concrete_recovery_outcome(text: str) -> bool:
    action = "\\b(calculate|calculates|calculating|compute|computes|computing|decode|decodes|decoding|decrypt|decrypts|decrypting|derive|derives|deriving|emit|emits|emitting|extract|extracts|extracting|print|prints|printing|produce|produces|producing|recover|recovers|recovering|return|returns|returning|solve|solves|solving|submit|submits|submitting)\\b"
    outcome = "\\b(answer|candidate|credential|flag|keystream|output|password|plaintext|plain\\s+text|result|secret|token)\\b"
    if re.search(action, text) and re.search(outcome, text):
        return True
    return bool(
        re.search(
            "\\b(compute|computes|computing|derive|derives|deriving|extract|extracts|extracting|recover|recovers|recovering)\\s+(?:a|an|the)?\\s*(key|keystream)\\b",
            text,
        )
    )
