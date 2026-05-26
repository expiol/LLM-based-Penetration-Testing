"""Recall and derived projections for run memory."""

from __future__ import annotations

from collections.abc import Mapping
import re

from killchain_docker.memory.entries import (
    DEFAULT_RUN_MEMORY_LIMIT,
    MEMORY_ENTRYPOINT_NAME,
    MemoryEntry,
    MemoryIndexSnapshot,
)


def recall_memory_entries(
    data: Mapping[str, str],
    *,
    limit: int = DEFAULT_RUN_MEMORY_LIMIT,
) -> tuple[MemoryEntry, ...]:
    selected_limit = max(1, limit)
    return tuple(
        MemoryEntry(str(key), str(value))
        for key, value in list(data.items())[-selected_limit:]
    )


def memory_index_snapshot(
    data: Mapping[str, str],
    *,
    title: str = "Run Memory",
    limit: int = DEFAULT_RUN_MEMORY_LIMIT,
) -> MemoryIndexSnapshot:
    entries = recall_memory_entries(data, limit=limit)
    lines = [f"# {title}", "", f"## {MEMORY_ENTRYPOINT_NAME}"]
    if not entries:
        lines.append("No grounded memory has been recorded yet.")
    else:
        for entry in entries:
            lines.append(f"- [{entry.key}](memory://{entry.key}) - {entry.value}")
    return MemoryIndexSnapshot(entries=entries, index_markdown="\n".join(lines))


def memory_prompt_mapping(
    data: Mapping[str, str],
    *,
    limit: int = DEFAULT_RUN_MEMORY_LIMIT,
) -> dict[str, str]:
    return {
        entry.key: entry.value
        for entry in recall_memory_entries(data, limit=max(1, limit))
    }


def memory_numeric_hints(
    data: Mapping[str, str],
    *,
    limit: int = 100000000,
    max_hints: int = 12,
    recall_limit: int = DEFAULT_RUN_MEMORY_LIMIT,
) -> list[dict[str, object]]:
    """Extract bounded numeric hints from memory keys and values."""

    candidates: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()
    counter_words = re.compile(
        "(?:count|counter|skip|limit|length|size|offset|round|iteration|bound)",
        re.IGNORECASE,
    )

    def add(label: str, value: int) -> None:
        key = (label, value)
        if value < 0 or value > limit or key in seen:
            return
        seen.add(key)
        candidates.append({"label": label, "value": value, "source": "run_memory"})

    def scan_text(text: str) -> None:
        for match in re.finditer(
            "\\b([A-Za-z_][A-Za-z0-9_ -]{0,40})\\s*[:=]\\s*(0x[0-9a-fA-F]+|\\d+)\\b",
            text,
        ):
            label = counter_label(match.group(1), counter_words)
            if not label:
                continue
            parsed = parse_numeric_token(match.group(2))
            if parsed is not None:
                add(label[:48], parsed)

    for entry in recall_memory_entries(data, limit=recall_limit):
        key = entry.key
        value = entry.value
        if counter_words.search(key):
            for token in re.findall("\\b0x[0-9a-fA-F]+\\b|\\b\\d+\\b", value):
                parsed = parse_numeric_token(token)
                if parsed is not None:
                    add(key[:48], parsed)
        scan_text(value)
        if len(candidates) >= max_hints:
            break
    return candidates[:max_hints]


def counter_label(raw_label: str, counter_words: re.Pattern[str]) -> str:
    label = re.sub("\\s+", "_", raw_label.strip()).strip("_")
    if not label or not counter_words.search(label):
        return ""
    words = [word.lower() for word in re.findall("[A-Za-z]+", label)]
    for index, word in enumerate(words):
        if not counter_words.search(word):
            continue
        if index and words[index - 1] in {
            "corrected",
            "bounded",
            "expected",
            "actual",
            "declared",
        }:
            return f"{words[index - 1]}_{word}"
        return word
    return label


def parse_numeric_token(token: str) -> int | None:
    try:
        return int(token, 16) if token.lower().startswith("0x") else int(token)
    except ValueError:
        return None

