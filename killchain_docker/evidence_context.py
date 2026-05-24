"""Compact tool evidence snapshots for planner and worker prompts."""

from __future__ import annotations

import re
import json

from killchain_docker.state import EvidenceRecord, RunState


_HEX_BLOCK_RE = re.compile(r"(?:[0-9a-fA-F]{2}[\s:]){4,}")


def _has_hex_block(text: str) -> bool:
    """Return True if text contains a hex dump-like block."""
    return bool(_HEX_BLOCK_RE.search(text[:2000]))


class EvidenceContextBuilder:
    """Build a small, chronological evidence view from recent tool output.

    Uses progressive summarization: full detail for recent records, compressed
    for older ones. Category-aware window sizing for crypto/rev/forensics.
    """

    def __init__(
        self,
        *,
        max_records: int = 14,
        max_text_preview: int = 1400,
        max_key_lines: int = 16,
        max_total_chars: int = 18000,
        category: str = "misc",
    ) -> None:
        if category in ("crypto", "rev", "forensics"):
            self.max_records = 16
            self.max_text_preview = 1800
        else:
            self.max_records = max_records
            self.max_text_preview = max_text_preview
        self.max_key_lines = max_key_lines
        self.max_total_chars = max_total_chars

    def build(self, state: RunState, allowed_capabilities: set | None = None) -> list[dict[str, object]]:
        out: list[dict[str, object]] = []
        total_chars = 0
        selected = self._select_records(state, allowed_capabilities=allowed_capabilities)
        total_selected = len(selected)
        for rank, evidence in enumerate(selected):
            # Progressive detail: last 3 full, next 5 medium, rest compressed
            tier_offset = total_selected - 1 - rank
            if tier_offset < 3:
                tier = "full"
            elif tier_offset < 8:
                tier = "medium"
            else:
                tier = "compressed"

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

            if evidence.tool_name == "script_exec":
                item.update(self._script_context(ctx, tier=tier))
            else:
                item.update(self._generic_context(ctx, evidence=evidence, tier=tier))

            if len(item) > 5:
                item_chars = len(json.dumps(item, ensure_ascii=True))
                if out and total_chars + item_chars > self.max_total_chars:
                    break
                total_chars += item_chars
                out.append(item)
        return out

    def _select_records(self, state: RunState, allowed_capabilities: set | None = None) -> list[EvidenceRecord]:
        scored: list[tuple[float, int, EvidenceRecord]] = []
        records = list(state.evidence.values())
        total = max(1, len(records))
        for index, evidence in enumerate(records):
            # Filter out evidence from capabilities this worker can't use
            if allowed_capabilities and evidence.capability:
                if evidence.capability not in {
                    cap.value if hasattr(cap, "value") else str(cap)
                    for cap in allowed_capabilities
                }:
                    continue
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context")
            if not isinstance(ctx, dict):
                ctx = {}
            score = self._score_record(evidence, ctx)
            if score <= 0:
                continue
            # Stronger recency: 0-8 (was 0-4) so recent evidence can overcome tool-type bias
            recency_bonus = min(8.0, (index + 1) / total * 8.0)
            # Near-miss evidence is the most actionable signal — boost it strongly
            near_miss_boost = 6.0 if ctx.get("near_miss_candidates") else 0.0
            scored.append((score + recency_bonus + near_miss_boost, index, evidence))

        mandatory_ids: set[str] = set()
        for tool_name in ("script_exec", "shell_exec"):
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

    def _score_record(self, evidence: EvidenceRecord, ctx: dict[str, object]) -> float:
        tool_name = evidence.tool_name
        summary = evidence.summary
        stdout = _evidence_text(evidence, ctx, "stdout")
        score = 0.0
        if tool_name == "script_exec":
            score += 2.0
            if stdout:
                score += 3.0
            if ctx.get("failure_kind") not in (None, "", "none"):
                score += 4.0
            # Structural signals: hex data present
            if any(token in stdout.lower() for token in ("0x", "\\x", "hexdump", "xxd")) or _has_hex_block(stdout):
                score += 6.0
            # Structural signals: disassembly or binary analysis present
            if any(token in stdout.lower() for token in ("disassembly", "objdump", "instruction")):
                score += 7.0
            # Structural signals: numeric/algorithmic data present
            if any(token in stdout.lower() for token in ("uint", "int32", "byte", "bit")):
                score += 5.0
        elif tool_name == "shell_exec":
            score += 4.0
            if stdout:
                score += 2.0
        elif tool_name in {
            "objdump", "radare2", "strings_cmd", "gdb", "ltrace", "strace",
            "file_cmd", "checksec", "binwalk", "exiftool", "sqlite3",
            "tshark", "jadx", "john", "fcrackzip",
        }:
            score += 3.0
            if stdout:
                score += 2.0
        if ctx.get("functions") or ctx.get("sections") or ctx.get("binary_info"):
            score += 3.0
        if any(token in stdout.lower() for token in ("0x", "\\x", "hexdump", "xxd")) or _has_hex_block(stdout):
            score += 5.0
        if any(token in stdout.lower() for token in ("disassembly", "objdump", "instruction", "sym.", "main")):
            score += 5.0
        if any(token in stdout.lower() for token in ("uint", "int32", "byte", "bit", "xor", "shift", "lfsr")):
            score += 4.0
        if ctx.get("flag_candidates"):
            score += 10.0
        return score

    def _script_context(self, ctx: dict[str, object], *, tier: str = "full") -> dict[str, object]:
        stdout = _string(ctx.get("stdout"))
        stderr = _string(ctx.get("stderr"))
        preview_width = {"full": 3000, "medium": 1800, "compressed": 600}[tier]
        result: dict[str, object] = {
            "returncode": ctx.get("returncode"),
            "result_quality": ctx.get("result_quality"),
            "partial_reason": ctx.get("partial_reason"),
            "failure_kind": ctx.get("failure_kind"),
            "failure_detail": ctx.get("failure_detail"),
            "flag_candidates": _trim_list(ctx.get("flag_candidates"), limit=8, width=240),
            "near_miss_candidates": _trim_list(ctx.get("near_miss_candidates"), limit=8, width=240),
            "stdout_key_lines": self._key_lines(stdout),
            "stdout_preview": self._trim_text(stdout, width=preview_width),
        }
        if stderr:
            result["stderr_key_lines"] = self._key_lines(stderr)
            result["stderr_preview"] = self._trim_text(stderr, width=min(preview_width, 900))
        for key in ("bare_token_candidates", "bracket_span_candidates"):
            values = _trim_list(ctx.get(key), limit=8, width=240)
            if values:
                result[key] = values
        return _compact(result)

    def _generic_context(
        self,
        ctx: dict[str, object],
        *,
        evidence: EvidenceRecord,
        tier: str = "full",
    ) -> dict[str, object]:
        keep_keys = (
            "returncode",
            "path",
            "commands",
            "line_count",
            "function_count",
            "instruction_count",
            "file_format",
            "functions",
            "sections",
            "strings",
            "binary_info",
            "has_crypto_refs",
            "has_network_refs",
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
        preview_width = {"full": 2200, "medium": 1200, "compressed": 500}[tier]
        stdout = _evidence_text(evidence, ctx, "stdout")
        stderr = _evidence_text(evidence, ctx, "stderr")
        if stdout:
            out["stdout_key_lines"] = self._key_lines(stdout)
            out["stdout_preview"] = self._trim_text(stdout, width=preview_width)
        if stderr:
            out["stderr_key_lines"] = self._key_lines(stderr)
            out["stderr_preview"] = self._trim_text(stderr, width=min(preview_width, 700))
        return out

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


def _evidence_text(evidence: EvidenceRecord, ctx: dict[str, object], key: str) -> str:
    ctx_value = _string(ctx.get(key))
    if ctx_value:
        return ctx_value
    result = evidence.result if isinstance(evidence.result, dict) else {}
    return _string(result.get(key))


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
