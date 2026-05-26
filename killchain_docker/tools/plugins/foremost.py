"""foremost — file carving from disk images or binary blobs.

Supports:
  - Automatic file type carving (images, documents, archives, etc.)
  - Rich output parsing: carved file types, counts, audit.txt parsing
  - Typed state signals: Artifact per carved file
"""

from __future__ import annotations
import re
import shlex
from typing import Any
from killchain_docker.state.domain import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command

_AUDIT_RE = re.compile("^\\d+:\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)", re.MULTILINE)
_FILES_MARKER = "__KILLCHAIN_FOREMOST_FILES__"
_AUDIT_MARKER = "__KILLCHAIN_FOREMOST_AUDIT__"
_KNOWN_TYPE_DIRS = {
    "jpg",
    "png",
    "gif",
    "bmp",
    "pdf",
    "doc",
    "zip",
    "rar",
    "exe",
    "elf",
    "htm",
    "ole",
    "all",
}


class ForemostPlugin:
    name = "foremost"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        output_expr = _durable_output_expr(
            source_path=path, requested_output_dir=output_dir, files_root=files_root
        )
        cmd = f'_kc_src={shlex.quote(path)}; _kc_out={output_expr}; rm -rf "$_kc_out"; mkdir -p "$(dirname "$_kc_out")"; foremost -i "$_kc_src" -o "$_kc_out"; _kc_rc=$?; printf "%s\\n" "{_FILES_MARKER}"; find "$_kc_out" -type f ! -name audit.txt -printf "%p\\t%s\\n" 2>/dev/null | sort; printf "%s\\n" "{_AUDIT_MARKER}"; find "$_kc_out" -name audit.txt -type f -print -exec sed -n "1,200p" {{}} \\; 2>/dev/null || true; exit "$_kc_rc"'
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd, files_root, preserve_relative_paths=(".autopentest_artifacts",)
                ),
            ],
            request.timeout_s,
        )


def _safe_stem(path: str) -> str:
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or "artifact"
    return re.sub("[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *, source_path: str, requested_output_dir: str, files_root: str
) -> str:
    """Return a shell expression for a preserved foremost output directory."""
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = ""
    if requested:
        suffix = f"_{_safe_stem(requested)}"
    return f'"$CTF_FILES_ROOT/.autopentest_artifacts/foremost_{_safe_stem(source_path)}{suffix}_$$"'


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    carved_records = _parse_carved_records(stdout)
    carved_files = [record["path"] for record in carved_records]
    type_counts: dict[str, int] = {}
    for record in carved_records:
        kind = _carved_kind(record["path"])
        type_counts[kind] = type_counts.get(kind, 0) + 1
    artifacts: list[Artifact] = []
    for record in carved_records[:80]:
        fpath = record["path"]
        kind = _carved_kind(fpath)
        artifacts.append(
            Artifact(
                path=fpath,
                kind=f"foremost_{kind}",
                source="foremost",
                size=record.get("size"),
                metadata={"source_file": path},
            )
        )
    flags = _flag_candidates_from(stdout, source="foremost")
    summary = f"foremost {path}: {len(carved_files)} file(s) carved"
    if type_counts:
        type_parts = [
            f"{count} {kind}"
            for kind, count in sorted(type_counts.items(), key=lambda x: -x[1])[:4]
        ]
        summary += f" ({', '.join(type_parts)})"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "carved_count": len(carved_files),
        "carved_files": carved_files[:80],
        "carved_file_records": carved_records[:80],
        "carved_files_durable": True,
    }
    if type_counts:
        output_context["type_counts"] = type_counts
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _parse_carved_records(stdout: str) -> list[dict[str, Any]]:
    lines = stdout.splitlines()
    records: list[dict[str, Any]] = []
    in_files = False
    for line in lines:
        line_s = line.strip()
        if line_s == _FILES_MARKER:
            in_files = True
            continue
        if line_s == _AUDIT_MARKER:
            in_files = False
            continue
        if not in_files or not line_s:
            continue
        path, size = _split_find_record(line_s)
        if not path or path.endswith("/audit.txt"):
            continue
        records.append({"path": path, "size": size})
    return records


def _split_find_record(line: str) -> tuple[str, int | None]:
    if "\t" not in line:
        return (line, None)
    path, raw_size = line.rsplit("\t", 1)
    try:
        size = int(raw_size)
    except ValueError:
        size = None
    return (path, size)


def _carved_kind(path: str) -> str:
    parts = [part.lower() for part in path.split("/") if part]
    for part in reversed(parts[:-1]):
        if part in _KNOWN_TYPE_DIRS:
            return part
    name = parts[-1] if parts else ""
    if "." in name:
        ext = name.rsplit(".", 1)[-1]
        return ext or "unknown"
    return "unknown"
