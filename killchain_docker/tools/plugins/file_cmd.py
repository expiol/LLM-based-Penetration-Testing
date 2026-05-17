"""file — file type identification.

Supports:
  - MIME type and detailed file description
  - Rich output parsing: binary traits, file category classification
  - Typed state signals: Artifact with classified kind
"""

from __future__ import annotations

import re
from typing import Any

from killchain_docker.state import Artifact
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


# Map file(1) output keywords → artifact kind
_KIND_MAP: list[tuple[str, str]] = [
    ("elf", "binary"),
    ("pe32", "binary"),
    ("mach-o", "binary"),
    ("executable", "binary"),
    ("shared object", "binary"),
    ("python", "source"),
    ("shell script", "source"),
    ("perl", "source"),
    ("ruby", "source"),
    ("php", "source"),
    ("javascript", "source"),
    ("c source", "source"),
    ("java", "source"),
    ("html", "source"),
    ("xml", "source"),
    ("json", "source"),
    ("ascii text", "text"),
    ("utf-8", "text"),
    ("unicode", "text"),
    ("zip archive", "archive"),
    ("gzip", "archive"),
    ("tar archive", "archive"),
    ("bzip2", "archive"),
    ("xz compressed", "archive"),
    ("7-zip", "archive"),
    ("rar archive", "archive"),
    ("png image", "image"),
    ("jpeg image", "image"),
    ("gif image", "image"),
    ("bmp", "image"),
    ("tiff", "image"),
    ("pdf document", "document"),
    ("microsoft", "document"),
    ("openoffice", "document"),
    ("sqlite", "database"),
    ("pcap", "pcap"),
    ("tcpdump", "pcap"),
    ("certificate", "certificate"),
    ("private key", "key"),
    ("public key", "key"),
    ("pgp", "key"),
    ("ssh", "key"),
]

_ARCH_RE = re.compile(r"\b(x86-64|x86_64|i386|i686|ARM|aarch64|MIPS|PowerPC|SPARC|RISC-V)\b", re.IGNORECASE)
_STRIPPED_RE = re.compile(r"\b(not stripped|stripped)\b", re.IGNORECASE)
_LINKED_RE = re.compile(r"\b(statically linked|dynamically linked)\b", re.IGNORECASE)


class FilePlugin:
    name = "file_cmd"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        return _run(
            self.name,
            [*self.argv_prefix, "bash", "-c", f"file -b {path} && file -b --mime-type {path}"],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    stdout = (result.stdout or "").strip()
    stderr = result.stderr or ""
    status = _status(result)

    lines = stdout.splitlines()
    file_type = lines[0].strip() if lines else ""
    mime_type = lines[1].strip() if len(lines) > 1 else ""

    # -- Classify kind -------------------------------------------------------
    kind = "unknown"
    lower = file_type.lower()
    for keyword, classified_kind in _KIND_MAP:
        if keyword in lower:
            kind = classified_kind
            break

    # -- Binary traits -------------------------------------------------------
    arch = ""
    m = _ARCH_RE.search(file_type)
    if m:
        arch = m.group(1)

    stripped = ""
    m = _STRIPPED_RE.search(file_type)
    if m:
        stripped = m.group(1).lower()

    linking = ""
    m = _LINKED_RE.search(file_type)
    if m:
        linking = m.group(1).lower()

    # -- Artifact ------------------------------------------------------------
    artifacts: list[Artifact] = []
    if path:
        meta: dict[str, Any] = {"file_type": file_type}
        if mime_type:
            meta["mime_type"] = mime_type
        if arch:
            meta["arch"] = arch
        if stripped:
            meta["stripped"] = stripped
        if linking:
            meta["linking"] = linking
        artifacts.append(Artifact(
            path=path, kind=kind, source="file", metadata=meta,
        ))

    # -- Flags ---------------------------------------------------------------
    flags = _flag_candidates_from(file_type, source="file")

    # -- Summary -------------------------------------------------------------
    summary = f"file {path}: {file_type[:120]}"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    # -- output_context ------------------------------------------------------
    output_context: dict[str, Any] = {
        "path": path,
        "file_type": file_type,
        "kind": kind,
    }
    if mime_type:
        output_context["mime_type"] = mime_type
    if arch:
        output_context["arch"] = arch
    if stripped:
        output_context["stripped"] = stripped == "stripped"
    if linking:
        output_context["linking"] = linking

    return ToolOutput(
        status=status,
        summary=summary,
        output_text=stdout,
        raw_log=_truncate(stdout + stderr, 4000),
        output_context=output_context,
        flag_candidates=flags,
        artifacts=artifacts,
    )
