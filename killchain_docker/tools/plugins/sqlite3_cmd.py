"""sqlite3 — SQLite database queries.

Supports:
  - Arbitrary SQL queries and schema inspection
  - Rich output parsing: table detection, credential tables, data preview
  - Typed state signals: Credential for user/password tables, Artifact for DB file
"""

from __future__ import annotations

import re
from typing import Any

from killchain_docker.state import Artifact, Credential
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
    _truncate,
)


# Heuristic: columns that likely contain usernames or passwords
_USER_COLS = frozenset({"user", "username", "login", "email", "name", "admin"})
_PASS_COLS = frozenset({"pass", "password", "passwd", "secret", "hash", "token", "pwd"})
_CRED_TABLES = frozenset({
    "users", "user", "accounts", "account", "admins", "admin",
    "credentials", "logins", "members", "auth",
})


class Sqlite3Plugin:
    name = "sqlite3"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        query = str(request.metadata.get("query") or ".tables")
        # Use -header -separator for structured output
        cmd = f"sqlite3 -header -separator '|' {path} '{query}'"
        return _run(self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s)


# ---------------------------------------------------------------------------
# Output builder
# ---------------------------------------------------------------------------

def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    query = str(request.metadata.get("query") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)

    rows = [line for line in stdout.splitlines() if line.strip()]
    is_table_listing = query.strip().lower() in (".tables", ".schema")

    # -- Parse tables from .tables output ------------------------------------
    tables: list[str] = []
    if is_table_listing:
        for line in rows:
            for table in line.split():
                table = table.strip()
                if table:
                    tables.append(table)

    # -- Detect credential tables --------------------------------------------
    credential_tables: list[str] = [
        t for t in tables if t.lower() in _CRED_TABLES
    ]

    # -- Parse columnar results (header|col1|col2 format) --------------------
    columns: list[str] = []
    data_rows: list[list[str]] = []
    if rows and "|" in rows[0] and not is_table_listing:
        columns = [c.strip().lower() for c in rows[0].split("|")]
        for row in rows[1:]:
            data_rows.append([c.strip() for c in row.split("|")])

    # -- Extract credentials from columnar data ------------------------------
    credentials: list[Credential] = []
    if columns:
        user_idx: int | None = None
        pass_idx: int | None = None
        for i, col in enumerate(columns):
            if col in _USER_COLS:
                user_idx = i
            if col in _PASS_COLS:
                pass_idx = i

        if user_idx is not None:
            for row in data_rows[:50]:
                if user_idx < len(row):
                    username = row[user_idx]
                    passwd = row[pass_idx] if pass_idx is not None and pass_idx < len(row) else ""
                    if username:
                        credentials.append(Credential(
                            credential_id=f"sqlite3-{username[:32]}",
                            username=username,
                            secret_ref=f"sqlite:{passwd}" if passwd else "sqlite:unknown",
                            credential_type="database",
                            source="sqlite3",
                            metadata={"db_path": path, "query": query[:200]},
                        ))

    # -- Artifact ------------------------------------------------------------
    artifacts: list[Artifact] = []
    if path:
        artifacts.append(Artifact(
            path=path,
            kind="sqlite_database",
            source="sqlite3",
            metadata={
                "tables": tables[:20] if tables else [],
                "row_count": len(data_rows),
            },
        ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(stdout, source="sqlite3")

    # -- Summary -------------------------------------------------------------
    summary = f"sqlite3 {path}: {len(rows)} row(s)"
    if tables:
        summary = f"sqlite3 {path}: {len(tables)} table(s)"
        if credential_tables:
            summary += f" (credential table(s): {', '.join(credential_tables[:3])})"
    if credentials:
        summary += f", {len(credentials)} credential(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "query": query,
        "row_count": len(rows),
    }
    if tables:
        output_context["tables"] = tables
    if credential_tables:
        output_context["credential_tables"] = credential_tables
    if columns:
        output_context["columns"] = columns
    if data_rows:
        output_context["data_preview"] = [
            dict(zip(columns, row)) for row in data_rows[:10]
        ]

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        credentials=credentials,
        artifacts=artifacts,
    )
