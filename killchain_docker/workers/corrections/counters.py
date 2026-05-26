"""Bounded numeric hints for repairing unbounded script attempts."""

from __future__ import annotations

import re

from killchain_docker.memory.projection import RunMemoryProjection
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem


def large_counter_values(text: str, *, limit: int = 5000000) -> list[int]:
    values: list[int] = []
    seen: set[int] = set()
    for match in re.finditer("\\b0x[0-9a-fA-F]{6,}\\b|\\b\\d{7,}\\b", text):
        token = match.group(0)
        try:
            value = int(token, 16) if token.lower().startswith("0x") else int(token)
        except ValueError:
            continue
        if value <= limit or value in seen:
            continue
        seen.add(value)
        values.append(value)
        if len(values) >= 8:
            break
    return values


def bounded_counter_candidates(
    *, state: RunState, task: TodoItem, limit: int = 5000000
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    counter_words = re.compile(
        "(?:count|counter|skip|limit|length|size|offset|round|iteration|bound)",
        re.IGNORECASE,
    )

    def add(label: str, value: int, source: str) -> None:
        key = (label, value)
        if value < 0 or value > limit or key in seen:
            return
        seen.add(key)
        candidates.append({"label": label, "value": value, "source": source})

    def scan_text(source: str, text: str) -> None:
        for match in re.finditer(
            "\\b([A-Za-z_][A-Za-z0-9_ -]{0,40})\\s*[:=]\\s*(0x[0-9a-fA-F]+|\\d+)\\b",
            text,
        ):
            label = re.sub("\\s+", "_", match.group(1).strip()).strip("_")
            if not label or not counter_words.search(label):
                continue
            words = [word.lower() for word in re.findall("[A-Za-z]+", label)]
            for index, word in enumerate(words):
                if counter_words.search(word):
                    if index and words[index - 1] in {
                        "corrected",
                        "bounded",
                        "expected",
                        "actual",
                        "declared",
                    }:
                        label = f"{words[index - 1]}_{word}"
                    else:
                        label = word
                    break
            token = match.group(2)
            try:
                value = int(token, 16) if token.lower().startswith("0x") else int(token)
            except ValueError:
                continue
            add(label[:48], value, source)

    scan_text("todo.goal", task.goal)
    scan_text("todo.constraints", "\n".join(task.constraints))
    scan_text("todo.success_criteria", "\n".join(task.success_criteria))
    for key, value in task.context.items():
        if isinstance(value, int) and counter_words.search(str(key)):
            add(str(key)[:48], value, "todo.context")
        elif isinstance(value, str):
            scan_text(f"todo.context.{key}", value)
    for hint in RunMemoryProjection(state).numeric_hints(limit=limit, max_hints=12):
        label = str(hint.get("label") or "")[:48]
        raw_value = hint.get("value")
        if not label or not isinstance(raw_value, int):
            continue
        add(label, raw_value, str(hint.get("source") or "run_memory"))
        if len(candidates) >= 12:
            break
    return candidates[:12]
