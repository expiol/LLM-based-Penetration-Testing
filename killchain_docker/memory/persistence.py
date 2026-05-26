"""Filesystem-backed durable memory persistence and recall."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from killchain_docker.memory.durable import (
    DurableMemoryRecord,
    DurableMemoryScope,
    DurableMemoryUpdate,
)
from killchain_docker.state.common import utc_now

INDEX_NAME = "MEMORY.md"
MAX_INDEX_LINES = 200
SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(text: str, *, fallback: str = "memory") -> str:
    cleaned = SLUG_RE.sub("-", text.lower()).strip("-")
    return cleaned[:80] or fallback


def _scope_dir(root: Path, scope: DurableMemoryScope, *, category: str | None,
               challenge: str | None) -> Path:
    if scope == DurableMemoryScope.GLOBAL:
        return root / "global"
    if scope == DurableMemoryScope.CATEGORY:
        if not category:
            raise ValueError("category scope requires a category")
        return root / "category" / slugify(category, fallback="misc")
    if scope == DurableMemoryScope.CHALLENGE:
        if not challenge:
            raise ValueError("challenge scope requires a challenge")
        return root / "challenge" / slugify(challenge, fallback="unnamed")
    raise ValueError(f"unknown scope: {scope}")


def _format_frontmatter(record: DurableMemoryRecord) -> str:
    lines = ["---"]
    lines.append(f"slug: {record.slug}")
    lines.append(f"key: {json.dumps(record.key, ensure_ascii=False)}")
    lines.append(f"title: {json.dumps(record.title, ensure_ascii=False)}")
    lines.append(f"scope: {record.scope.value}")
    if record.category:
        lines.append(f"category: {json.dumps(record.category, ensure_ascii=False)}")
    if record.challenge:
        lines.append(f"challenge: {json.dumps(record.challenge, ensure_ascii=False)}")
    runs_payload = json.dumps(record.run_ids, ensure_ascii=False)
    lines.append(f"run_ids: {runs_payload}")
    lines.append(f"created_at: {record.created_at.isoformat()}")
    lines.append(f"updated_at: {record.updated_at.isoformat()}")
    lines.append("---")
    return "\n".join(lines)


_SIMPLE_FIELD_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$")


def _parse_frontmatter(text: str) -> tuple[dict[str, object], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---", 4)
    if end == -1:
        return {}, text
    block = text[4:end]
    body = text[end + len("\n---"):].lstrip("\n")
    data: dict[str, object] = {}
    for line in block.splitlines():
        match = _SIMPLE_FIELD_RE.match(line)
        if not match:
            continue
        name, raw = match.group(1), match.group(2).strip()
        if not raw:
            data[name] = ""
            continue
        try:
            data[name] = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            data[name] = raw
    return data, body


def _read_record(path: Path) -> DurableMemoryRecord | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    meta, body = _parse_frontmatter(text)
    slug = str(meta.get("slug") or path.stem).strip()
    key = str(meta.get("key") or slug).strip()
    if not key:
        return None
    scope_raw = str(meta.get("scope") or DurableMemoryScope.CHALLENGE.value).lower()
    try:
        scope = DurableMemoryScope(scope_raw)
    except ValueError:
        scope = DurableMemoryScope.CHALLENGE
    runs = meta.get("run_ids") or []
    if not isinstance(runs, list):
        runs = []
    created = _coerce_dt(meta.get("created_at"))
    updated = _coerce_dt(meta.get("updated_at"))
    return DurableMemoryRecord(
        slug=slug,
        key=key,
        value=body.strip(),
        scope=scope,
        category=str(meta["category"]).strip() if meta.get("category") else None,
        challenge=str(meta["challenge"]).strip() if meta.get("challenge") else None,
        title=str(meta.get("title") or "").strip(),
        run_ids=[str(item) for item in runs if str(item).strip()],
        created_at=created,
        updated_at=updated,
    )


def _coerce_dt(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            return utc_now()
    return utc_now()


def _scan_records(scope_dir: Path) -> list[DurableMemoryRecord]:
    if not scope_dir.is_dir():
        return []
    records: list[DurableMemoryRecord] = []
    for entry in sorted(scope_dir.iterdir()):
        if entry.name == INDEX_NAME or entry.suffix != ".md":
            continue
        record = _read_record(entry)
        if record is not None:
            records.append(record)
    return records


def _write_index(scope_dir: Path, *, title: str,
                 records: Iterable[DurableMemoryRecord]) -> None:
    scope_dir.mkdir(parents=True, exist_ok=True)
    lines = [f"# {title}", ""]
    sorted_records = sorted(records, key=lambda r: r.updated_at, reverse=True)
    for record in sorted_records[:MAX_INDEX_LINES]:
        label = record.title or record.key
        runs = f" ({len(record.run_ids)} run{'s' if len(record.run_ids) != 1 else ''})"
        lines.append(f"- [{label}]({record.slug}.md) — {record.key}{runs}")
    if not sorted_records:
        lines.append("(empty)")
    (scope_dir / INDEX_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")


class DurableMemoryStore:
    """Filesystem-backed cross-run memory."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def load_relevant(
        self,
        *,
        category: str | None = None,
        challenge: str | None = None,
    ) -> list[DurableMemoryRecord]:
        """Return all records visible to a run with the given category/challenge."""
        records: list[DurableMemoryRecord] = []
        records.extend(_scan_records(self.root / "global"))
        if category:
            records.extend(
                _scan_records(self.root / "category" / slugify(category, fallback="misc"))
            )
        if challenge:
            records.extend(
                _scan_records(
                    self.root / "challenge" / slugify(challenge, fallback="unnamed")
                )
            )
        return records

    def apply_updates(
        self,
        updates: Iterable[DurableMemoryUpdate],
        *,
        run_id: str,
        category: str | None,
        challenge: str | None,
    ) -> list[DurableMemoryRecord]:
        """Persist `updates`; merge into existing records by (scope, key)."""
        applied: list[DurableMemoryRecord] = []
        touched_dirs: set[Path] = set()
        for update in updates:
            scope_category = category if update.scope != DurableMemoryScope.GLOBAL else None
            scope_challenge = challenge if update.scope == DurableMemoryScope.CHALLENGE else None
            try:
                scope_dir = _scope_dir(
                    self.root,
                    update.scope,
                    category=category,
                    challenge=challenge,
                )
            except ValueError:
                continue
            scope_dir.mkdir(parents=True, exist_ok=True)
            existing = self._find_by_key(scope_dir, update.key)
            now = utc_now()
            if existing is not None:
                existing.value = update.value
                existing.title = update.title or existing.title
                existing.merge_run(run_id)
                existing.updated_at = now
                record = existing
            else:
                slug = self._unique_slug(scope_dir, update.key)
                record = DurableMemoryRecord(
                    slug=slug,
                    key=update.key,
                    value=update.value,
                    scope=update.scope,
                    category=scope_category if update.scope != DurableMemoryScope.GLOBAL else None,
                    challenge=scope_challenge,
                    title=update.title or update.key,
                    run_ids=[run_id] if run_id else [],
                    created_at=now,
                    updated_at=now,
                )
            self._write_record(scope_dir / f"{record.slug}.md", record)
            applied.append(record)
            touched_dirs.add(scope_dir)
        for scope_dir in touched_dirs:
            title = self._index_title(scope_dir)
            _write_index(
                scope_dir, title=title, records=_scan_records(scope_dir)
            )
        if applied:
            self._refresh_root_index()
        return applied

    def _find_by_key(
        self, scope_dir: Path, key: str
    ) -> DurableMemoryRecord | None:
        for record in _scan_records(scope_dir):
            if record.key == key:
                return record
        return None

    def _unique_slug(self, scope_dir: Path, key: str) -> str:
        base = slugify(key, fallback="memory")
        candidate = base
        index = 2
        while (scope_dir / f"{candidate}.md").exists():
            candidate = f"{base}-{index}"
            index += 1
        return candidate

    @staticmethod
    def _write_record(path: Path, record: DurableMemoryRecord) -> None:
        body = record.value.rstrip()
        text = f"{_format_frontmatter(record)}\n\n{body}\n"
        path.write_text(text, encoding="utf-8")

    @staticmethod
    def _index_title(scope_dir: Path) -> str:
        parts = scope_dir.relative_to(scope_dir.parent.parent if scope_dir.parent.name in {"category", "challenge"} else scope_dir.parent).parts
        return f"Durable Memory — {'/'.join(parts)}"

    def _refresh_root_index(self) -> None:
        if not self.root.exists():
            return
        lines = ["# Durable Memory", ""]
        for scope_label, sub in (
            ("Global", self.root / "global"),
            ("Category", self.root / "category"),
            ("Challenge", self.root / "challenge"),
        ):
            if not sub.exists():
                continue
            lines.append(f"## {scope_label}")
            if sub.name == "global":
                files = sorted(sub.glob("*.md"))
                for path in files:
                    if path.name == INDEX_NAME:
                        continue
                    lines.append(f"- [global/{path.name}](global/{path.name})")
            else:
                for child in sorted(p for p in sub.iterdir() if p.is_dir()):
                    lines.append(
                        f"- [{sub.name}/{child.name}/]({sub.name}/{child.name}/{INDEX_NAME})"
                    )
            lines.append("")
        (self.root / INDEX_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
