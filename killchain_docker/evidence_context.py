"""Compact tool evidence snapshots for planner and worker prompts."""

from __future__ import annotations

import re

from killchain_docker.state import EvidenceRecord, RunState


_HEX_BLOCK_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]){4,}")


def _has_hex_block(text: str) -> bool:
    """Return True if text contains a hex dump-like block."""
    return bool(_HEX_BLOCK_RE.search(text[:2000]))


class EvidenceContextBuilder:
    """Build a small, chronological evidence view from recent tool output."""

    def __init__(
        self,
        *,
        max_records: int = 16,
        max_text_preview: int = 1800,
        max_key_lines: int = 24,
    ) -> None:
        self.max_records = max_records
        self.max_text_preview = max_text_preview
        self.max_key_lines = max_key_lines

    def build(self, state: RunState) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        for evidence in self._select_records(state):
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context")
            if not isinstance(ctx, dict):
                ctx = {}

            item: dict[str, object] = {
                "evidence_id": evidence.evidence_id,
                "task_id": evidence.task_id,
                "tool_name": evidence.tool_name,
                "capability": evidence.capability,
                "summary": evidence.summary[:300],
            }
            if extracted.get("notes"):
                item["notes"] = _trim_list(extracted.get("notes"), limit=4, width=240)

            if evidence.tool_name == "script_execution":
                item.update(self._script_context(ctx))
            elif evidence.tool_name == "binary_disassembly":
                item.update(self._binary_disassembly_context(ctx))
            elif evidence.tool_name == "binary_run":
                item.update(self._binary_run_context(ctx))
            else:
                item.update(self._generic_context(ctx))

            if len(item) > 5:
                out.append(item)
        return out

    def _select_records(self, state: RunState) -> list[EvidenceRecord]:
        scored: list[tuple[float, int, EvidenceRecord]] = []
        records = list(state.evidence.values())
        total = max(1, len(records))
        for index, evidence in enumerate(records):
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context")
            if not isinstance(ctx, dict):
                ctx = {}
            score = self._score_record(evidence.tool_name, evidence.summary, ctx)
            if score <= 0:
                continue
            # Stronger recency: 0-8 (was 0-4) so recent evidence can overcome tool-type bias
            recency_bonus = min(8.0, (index + 1) / total * 8.0)
            # Near-miss evidence is the most actionable signal — boost it strongly
            near_miss_boost = 6.0 if ctx.get("near_miss_candidates") else 0.0
            scored.append((score + recency_bonus + near_miss_boost, index, evidence))

        mandatory_ids: set[str] = set()
        for tool_name in ("script_execution", "binary_disassembly", "binary_run"):
            for _score, _index, evidence in sorted(scored, key=lambda item: item[1], reverse=True):
                if evidence.tool_name == tool_name:
                    mandatory_ids.add(evidence.evidence_id)
                    break

        selected: list[tuple[float, int, EvidenceRecord]] = []
        for item in sorted(scored, key=lambda item: (-item[0], -item[1])):
            if item[2].evidence_id in mandatory_ids:
                continue
            selected.append(item)
            if len(selected) + len(mandatory_ids) >= self.max_records:
                break
        selected.extend(item for item in scored if item[2].evidence_id in mandatory_ids)
        return [evidence for _score, _index, evidence in sorted(selected, key=lambda item: item[1])]

    def _score_record(self, tool_name: str, summary: str, ctx: dict[str, object]) -> float:
        score = 0.0
        if tool_name == "script_execution":
            score += 2.0
            if ctx.get("stdout"):
                score += 3.0
            if ctx.get("failure_kind") not in (None, "", "none"):
                score += 4.0
            stdout = _string(ctx.get("stdout"))
            # Structural signals: hex data present
            if any(token in stdout.lower() for token in ("0x", "\\x", "hexdump", "xxd")) or _has_hex_block(stdout):
                score += 6.0
            # Structural signals: disassembly or binary analysis present
            if any(token in stdout.lower() for token in ("disassembly", "objdump", "instruction")):
                score += 7.0
            # Structural signals: numeric/algorithmic data present
            if any(token in stdout.lower() for token in ("uint", "int32", "byte", "bit")):
                score += 5.0
        elif tool_name == "binary_disassembly":
            score += 5.0  # reduced from 9 so recency can overcome old disassembly
            disassembly = ctx.get("disassembly")
            if isinstance(disassembly, dict) and disassembly:
                score += 5.0
        elif tool_name == "binary_run":
            score += 4.0
            runs = ctx.get("binary_runs")
            if isinstance(runs, dict) and runs:
                score += 2.0
        elif ctx.get("flag_candidates"):
            score += 10.0
        return score

    def _script_context(self, ctx: dict[str, object]) -> dict[str, object]:
        stdout = _string(ctx.get("stdout"))
        stderr = _string(ctx.get("stderr"))
        result: dict[str, object] = {
            "returncode": ctx.get("returncode"),
            "result_quality": ctx.get("result_quality"),
            "partial_reason": ctx.get("partial_reason"),
            "failure_kind": ctx.get("failure_kind"),
            "failure_detail": ctx.get("failure_detail"),
            "flag_candidates": _trim_list(ctx.get("flag_candidates"), limit=8, width=240),
            "near_miss_candidates": _trim_list(ctx.get("near_miss_candidates"), limit=8, width=240),
            "stdout_key_lines": self._key_lines(stdout),
            "stdout_preview": self._trim_text(stdout),
        }
        if stderr:
            result["stderr_key_lines"] = self._key_lines(stderr)
            result["stderr_preview"] = self._trim_text(stderr, width=900)
        for key in ("bare_token_candidates", "bracket_span_candidates"):
            values = _trim_list(ctx.get(key), limit=8, width=240)
            if values:
                result[key] = values
        return _compact(result)

    def _binary_disassembly_context(self, ctx: dict[str, object]) -> dict[str, object]:
        disassembly = ctx.get("disassembly")
        if not isinstance(disassembly, dict):
            return self._generic_context(ctx)

        binaries: dict[str, object] = {}
        for binary_name, raw_info in list(disassembly.items())[:4]:
            if not isinstance(raw_info, dict):
                continue
            info: dict[str, object] = {
                "binary_traits": raw_info.get("binary_traits"),
                "function_count_total": raw_info.get("function_count_total"),
                "function_count_kept": raw_info.get("function_count_kept"),
                "disassembly_truncated": raw_info.get("disassembly_truncated"),
                "rodata": _trim_list(raw_info.get("rodata"), limit=8, width=220),
                "analysis_window_previews": [
                    self._trim_text(str(window), width=900)
                    for window in _as_list(raw_info.get("analysis_windows"))[:3]
                ],
                "function_previews": self._function_previews(raw_info.get("functions")),
            }
            binaries[str(binary_name)] = _compact(info)
        return _compact({
            "inspected_binaries": _trim_list(ctx.get("inspected_binaries"), limit=8, width=200),
            "binary_traits": ctx.get("binary_traits"),
            "binaries": binaries,
            "flag_candidates": _trim_list(ctx.get("flag_candidates"), limit=8, width=240),
        })

    def _binary_run_context(self, ctx: dict[str, object]) -> dict[str, object]:
        runs = ctx.get("binary_runs")
        if not isinstance(runs, dict):
            return self._generic_context(ctx)

        compact_runs: dict[str, object] = {}
        for binary_name, raw_info in list(runs.items())[:4]:
            if not isinstance(raw_info, dict):
                continue
            invocations = []
            for invocation in _as_list(raw_info.get("invocations"))[:5]:
                if not isinstance(invocation, dict):
                    continue
                invocations.append({
                    "argv": _trim_list(invocation.get("argv"), limit=8, width=160),
                    "returncode": invocation.get("returncode"),
                    "stdout_preview": self._trim_text(_string(invocation.get("stdout")), width=600),
                    "stderr_preview": self._trim_text(_string(invocation.get("stderr")), width=600),
                })
            compact_runs[str(binary_name)] = {"invocations": invocations}
        return _compact({
            "inspected_binaries": _trim_list(ctx.get("inspected_binaries"), limit=8, width=200),
            "binary_runs": compact_runs,
            "flag_candidates": _trim_list(ctx.get("flag_candidates"), limit=8, width=240),
        })

    def _generic_context(self, ctx: dict[str, object]) -> dict[str, object]:
        keep_keys = (
            "files_root",
            "inspected_files",
            "inspected_sources",
            "inspected_binaries",
            "challenge_files",
            "source_files",
            "binary_files",
            "interesting_routes",
            "secret_files",
            "security_issues",
            "flag_candidates",
            "decoded_text_previews",
        )
        out: dict[str, object] = {}
        for key in keep_keys:
            value = ctx.get(key)
            if isinstance(value, str):
                out[key] = self._trim_text(value, width=500)
            elif isinstance(value, list):
                out[key] = _trim_list(value, limit=8, width=240)
            elif value not in (None, "", [], {}):
                out[key] = value
        return out

    def _function_previews(self, functions: object) -> list[dict[str, object]]:
        previews: list[dict[str, object]] = []
        for function in _as_list(functions)[:3]:
            if not isinstance(function, dict):
                continue
            previews.append(_compact({
                "name": function.get("name"),
                "size_lines": function.get("size_lines"),
                "truncated": function.get("truncated"),
                "xref_strings": _trim_list(function.get("xref_strings"), limit=8, width=180),
                "disassembly_preview": self._trim_text(_string(function.get("disassembly")), width=1200),
            }))
        return previews

    def _key_lines(self, text: str) -> list[str]:
        if not text:
            return []
        # Generic pattern categories: hex data, errors, numeric/crypto terms
        needles = (
            "hex", "xxd", "byte", "uint", "int32", "0x",
            "cipher", "plain", "encrypt", "decrypt", "key",
            "xor", "shr", "shl", "sar", "rol", "ror",
            "error", "exception", "warning", "too many", "timeout",
            "flag", "secret", "token",
        )
        lines: list[str] = []
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            lower = line.lower()
            looks_hex_dump = (
                bool(line[:8].replace(":", "").replace(" ", ""))
                and ":" in line
                and any(char in line for char in "abcdefABCDEF0123456789")
            )
            if any(needle in lower for needle in needles) or looks_hex_dump:
                lines.append(self._trim_text(line, width=260))
            if len(lines) >= self.max_key_lines:
                break
        if lines:
            return lines
        return [self._trim_text(line.strip(), width=260) for line in text.splitlines()[:8] if line.strip()]

    def _trim_text(self, text: str, *, width: int | None = None) -> str:
        width = width or self.max_text_preview
        if len(text) <= width:
            return text
        return text[:width].rstrip() + f"... [truncated {len(text) - width} chars]"


def _compact(values: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in values.items() if value not in (None, "", [], {})}


def _string(value: object) -> str:
    return value if isinstance(value, str) else ""


def _as_list(value: object) -> list[object]:
    return value if isinstance(value, list) else []


def _trim_list(value: object, *, limit: int, width: int) -> list[object]:
    out: list[object] = []
    for item in _as_list(value)[:limit]:
        if isinstance(item, str):
            out.append(item if len(item) <= width else item[:width].rstrip() + "...")
        elif isinstance(item, dict):
            compact: dict[str, object] = {}
            for key, raw_value in item.items():
                if isinstance(raw_value, str):
                    compact[key] = (
                        raw_value if len(raw_value) <= width else raw_value[:width].rstrip() + "..."
                    )
                elif isinstance(raw_value, (int, float, bool)) or raw_value is None:
                    compact[key] = raw_value
                elif isinstance(raw_value, list):
                    compact[key] = _trim_list(raw_value, limit=4, width=min(width, 160))
            out.append(_compact(compact))
        else:
            out.append(item)
    return out
