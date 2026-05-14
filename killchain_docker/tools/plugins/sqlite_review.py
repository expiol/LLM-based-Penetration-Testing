"""SQLite inspection tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FILE_TARGETS_SNIPPET

TOOL_NAME = "sqlite_review"

SCRIPT = r"""
import json
import re
import sqlite3
import sys
from pathlib import Path

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files").resolve()
database_files = payload.get("database_files") or []
max_files = int(payload.get("max_files", 6))

records = []
flag_candidates = []
table_index = {}
interesting_rows = []
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")

if not database_files:
    records.append({"type": "summary", "text": "SQLite review failed: missing required metadata.database_files."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_databases": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

targets = _resolve_file_targets(files_root, database_files, max_files=max_files, kind="database")
for target in targets:
    relpath = target["display"]
    path = Path(target["path"])
    inspected.append(relpath)
    tables = []
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
    except Exception as exc:
        records.append({"type": "note", "text": f"SQLite open failed for {relpath}: {type(exc).__name__}: {exc}"})
        continue

    try:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        tables = [str(row[0]) for row in cursor.fetchall()][:16]
        table_index[relpath] = tables
        for table in tables[:8]:
            try:
                table_sql = table.replace("'", "''")
                column_rows = conn.execute(f"PRAGMA table_info('{table_sql}')").fetchall()
                columns = [str(row[1]) for row in column_rows]
                if any(token in " ".join(columns).lower() for token in ("password", "secret", "token", "flag", "key")):
                    interesting_rows.append(f"{relpath}:{table}:schema")

                sample_rows = conn.execute(f"SELECT * FROM '{table_sql}' LIMIT 20").fetchall()
                for row in sample_rows:
                    values = []
                    for key in row.keys():
                        value = row[key]
                        if value is None:
                            continue
                        values.append(f"{key}={str(value)[:160]}")
                    joined = " | ".join(values)
                    lowered = joined.lower()
                    for flag in flag_re.findall(joined):
                        if flag not in flag_candidates:
                            flag_candidates.append(flag)
                    if any(token in lowered for token in ("password", "secret", "token", "bearer ", "api_key", "apikey", "flag{")):
                        interesting_rows.append(f"{relpath}:{table}:{joined[:180]}")
            except Exception as exc:
                records.append({"type": "note", "text": f"SQLite query failed for {relpath}:{table}: {type(exc).__name__}: {exc}"})
    finally:
        conn.close()

if not inspected:
    records.append({"type": "summary", "text": "SQLite review failed: no requested database files could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "database_files": database_files[:max_files], "inspected_databases": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

records.append({
    "type": "summary",
    "text": (
        f"SQLite review completed for {len(inspected)} database file(s): "
        f"{sum(len(v) for v in table_index.values())} table(s), {len(flag_candidates)} flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-sqlite-review",
    "title": "SQLite artifacts reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} SQLite/database artifact(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "sqlite_review", "tables": table_index},
})

if interesting_rows:
    records.append({
        "type": "finding",
        "finding_id": "finding-sqlite-interesting-rows",
        "title": "Interesting database rows or schemas found",
        "severity": "medium",
        "description": f"Detected {len(interesting_rows)} interesting row or schema hit(s) in bundled databases.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": interesting_rows[:8],
        "metadata": {"source": "sqlite_review", "interesting_rows": interesting_rows[:20]},
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-sqlite-flags",
        "title": "Flag-like token found in database content",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from bundled databases.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "sqlite_review", "flag_candidates": flag_candidates[:10]},
    })

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_databases": inspected,
    "tables": table_index,
    "interesting_rows": interesting_rows[:20],
    "flag_candidates": flag_candidates[:10],
    "manual_checks": [
        "Review tables containing credentials, tokens, or challenge state.",
        "Inspect sample rows for encoded values or hidden flags.",
        "Validate any recovered flag-like token before submission.",
    ],
})

for item in records:
    print(json.dumps(item, ensure_ascii=True))
"""

SCRIPT = SHARED_FILE_TARGETS_SNIPPET + SCRIPT


def build_arguments(request: ToolExecutionRequest) -> list[str]:
    payload = {
        "files_root": request.metadata.get("files_root", "/home/ctfplayer/ctf_files"),
        "database_files": request.metadata.get("database_files", []),
        "max_files": request.metadata.get("max_files", 6),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
