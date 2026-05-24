"""office.inspect — deterministic inspection for OOXML/ZIP office documents."""

from __future__ import annotations

import re
import shlex
from typing import Any

from killchain_docker.state import FlagCandidate
from killchain_docker.state import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.constants import FLAG_PATTERN, plausible_flag
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
)
from killchain_docker.tools.plugins._base import (
    _require,
    _run,
    _status,
    _truncate,
)
from killchain_docker.tools.plugins.workspace import protected_shell_command


_DOC_MARKER = "__KILLCHAIN_OFFICE_INSPECT_DOC__"
_ENTRY_MARKER = "__KILLCHAIN_OFFICE_INSPECT_ENTRY__"
_TEXT_MARKER = "__KILLCHAIN_OFFICE_INSPECT_TEXT__"
_ARTIFACT_MARKER = "__KILLCHAIN_OFFICE_INSPECT_ARTIFACT__"
_ERROR_MARKER = "__KILLCHAIN_OFFICE_INSPECT_ERROR__"
_SUMMARY_MARKER = "__KILLCHAIN_OFFICE_INSPECT_SUMMARY__"
_DEFAULT_MAX_ENTRIES = 260
_DEFAULT_MAX_ARTIFACTS = 60
_DEFAULT_MAX_EXTRACT_MB = 96
_DEFAULT_MAX_TEXT_CHARS = 1200
_OFFICE_INSPECT_PY = r'''
import os
import re
import sys
import hashlib
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

DOC = "__KILLCHAIN_OFFICE_INSPECT_DOC__"
ENTRY = "__KILLCHAIN_OFFICE_INSPECT_ENTRY__"
TEXT = "__KILLCHAIN_OFFICE_INSPECT_TEXT__"
ARTIFACT = "__KILLCHAIN_OFFICE_INSPECT_ARTIFACT__"
ERROR = "__KILLCHAIN_OFFICE_INSPECT_ERROR__"
SUMMARY = "__KILLCHAIN_OFFICE_INSPECT_SUMMARY__"

def clean(value, limit=400):
    return re.sub(r"\s+", " ", str(value).replace("\t", " ").replace("\n", " ")).strip()[:limit]

def safe_part(value):
    out = re.sub(r"[^A-Za-z0-9_.@%+=,-]+", "_", str(value).strip())
    return out.strip("._")[:80] or "file"

def safe_relpath(value):
    text = str(value).replace("\\", "/").strip().strip("/")
    parts = []
    for part in text.split("/"):
        if not part or part in {".", ".."}:
            continue
        parts.append(safe_part(part))
    return "/".join(parts) or "file"

def role_for(name):
    lowered = name.lower()
    if lowered.startswith("ppt/slides/slide") and lowered.endswith(".xml"):
        return "slide"
    if lowered.startswith("ppt/notesslides/notesslide") and lowered.endswith(".xml"):
        return "notes"
    if "comments" in lowered and lowered.endswith(".xml"):
        return "comments"
    if lowered in {"docprops/core.xml", "docprops/app.xml"} or "custom.xml" in lowered:
        return "properties"
    if lowered.endswith(".rels"):
        return "relationship"
    if "/media/" in lowered:
        return "media"
    if "/embeddings/" in lowered or "oleobject" in lowered:
        return "embedding"
    if lowered.endswith(".xml"):
        return "xml"
    return "file"

def ext_for(names):
    lowered = {name.lower() for name in names}
    if "[content_types].xml" in lowered and any(name.startswith("ppt/") for name in lowered):
        return "pptx"
    if "[content_types].xml" in lowered and any(name.startswith("word/") for name in lowered):
        return "docx"
    if "[content_types].xml" in lowered and any(name.startswith("xl/") for name in lowered):
        return "xlsx"
    return "zip"

def text_from_xml(data):
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        raw = data.decode("utf-8", "ignore")
        raw = re.sub(r"<[^>]+>", " ", raw)
        return clean(raw, 4000)
    parts = [part.strip() for part in root.itertext() if part and part.strip()]
    for element in root.iter():
        for key, value in element.attrib.items():
            if not value or not str(value).strip():
                continue
            key_name = key.rsplit("}", 1)[-1].lower()
            if key_name in {"descr", "description", "title", "name", "tooltip", "target", "val", "value"}:
                parts.append(str(value).strip())
    return clean(" | ".join(parts), 4000)

def should_extract(name, info):
    if info.is_dir():
        return False
    lowered = name.lower()
    if "/media/" in lowered or "/embeddings/" in lowered:
        return True
    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".mp4", ".mov", ".avi", ".wav", ".mp3", ".pdf", ".zip", ".bin")):
        return True
    return False

def main():
    src = Path(sys.argv[1])
    out_root = Path(sys.argv[2])
    max_entries = int(sys.argv[3])
    max_artifacts = int(sys.argv[4])
    max_bytes = int(sys.argv[5]) * 1024 * 1024
    max_text = int(sys.argv[6])
    out_root.mkdir(parents=True, exist_ok=True)

    try:
        zf = zipfile.ZipFile(src)
    except (OSError, zipfile.BadZipFile) as exc:
        print(f"{ERROR}\topen\t{clean(exc)}")
        print(f"{SUMMARY}\t0\t0\t0\t0")
        return

    with zf:
        infos = zf.infolist()
        names = [info.filename for info in infos]
        doc_type = ext_for(names)
        print(f"{DOC}\t{doc_type}\t{len(infos)}")
        text_count = 0
        artifact_count = 0
        artifact_bytes = 0
        errors = 0
        for info in infos[:max_entries]:
            name = info.filename
            role = role_for(name)
            print(f"{ENTRY}\t{clean(name)}\t{info.file_size}\t{info.compress_size}\t{role}")
            lowered = name.lower()
            if lowered.endswith((".xml", ".rels")) and info.file_size <= 4 * 1024 * 1024:
                try:
                    data = zf.read(info)
                except Exception as exc:
                    errors += 1
                    print(f"{ERROR}\tread\t{clean(name)}: {clean(exc)}")
                else:
                    text = text_from_xml(data)
                    if text:
                        print(f"{TEXT}\t{clean(name)}\t{role}\t{clean(text, max_text)}")
                        text_count += 1
            if should_extract(name, info):
                if artifact_count >= max_artifacts:
                    continue
                if info.file_size <= 0 or artifact_bytes + info.file_size > max_bytes:
                    continue
                try:
                    data = zf.read(info)
                except Exception as exc:
                    errors += 1
                    print(f"{ERROR}\tread\t{clean(name)}: {clean(exc)}")
                    continue
                dest = out_root / safe_relpath(name)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                artifact_count += 1
                artifact_bytes += len(data)
                print(f"{ARTIFACT}\t{dest}\t{len(data)}\t{role}\t{clean(name)}\t{digest}")
        print(f"{SUMMARY}\t{len(infos)}\t{text_count}\t{artifact_count}\t{errors}")

if __name__ == "__main__":
    main()
'''


class OfficeInspectPlugin:
    name = "office_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        max_entries = _positive_int(request.metadata.get("max_entries"), _DEFAULT_MAX_ENTRIES)
        max_artifacts = _positive_int(request.metadata.get("max_artifacts"), _DEFAULT_MAX_ARTIFACTS)
        max_extract_mb = _positive_int(request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB)
        max_text_chars = _positive_int(request.metadata.get("max_text_chars"), _DEFAULT_MAX_TEXT_CHARS)
        output_expr = _durable_output_expr(
            source_path=path,
            requested_output_dir=output_dir,
            files_root=files_root,
        )
        cmd = (
            f"_kc_src={shlex.quote(path)}; "
            f"_kc_out={output_expr}; "
            f"python3 -c {shlex.quote(_OFFICE_INSPECT_PY)} "
            f'"$_kc_src" "$_kc_out" {max_entries} {max_artifacts} '
            f"{max_extract_mb} {max_text_chars}"
        )
        return _run(
            self.name,
            [
                *self.argv_prefix,
                "bash",
                "-c",
                protected_shell_command(
                    cmd,
                    files_root,
                    preserve_relative_paths=(".autopentest_artifacts",),
                ),
            ],
            request.timeout_s,
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    source_path = str(request.metadata.get("path") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    records = _parse_records(stdout)
    artifacts = [
        Artifact(
            path=record["path"],
            kind=f"office_{_artifact_kind(record['path'], record.get('role'))}",
            source="office_inspect",
            size=record.get("size"),
            digest=record.get("digest"),
            metadata={
                "source_file": source_path,
                "source_entry": record.get("source_entry"),
                "office_role": record.get("role"),
            },
        )
        for record in records["artifacts"][:120]
    ]
    flags = _literal_flag_candidates(records["texts"], source_path)
    doc_type = records.get("doc_type") or "office"
    summary = (
        f"office.inspect {source_path}: {doc_type}, "
        f"{len(records['texts'])} text part(s), "
        f"{len(records['artifacts'])} embedded artifact(s)"
    )
    if records["errors"]:
        summary += f", {len(records['errors'])} read error(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"

    return ToolOutput(
        status=_status(result),
        summary=summary,
        output_text=_truncate(stdout, 6000),
        raw_log=_truncate(stdout + stderr, 9000),
        output_context={
            "path": source_path,
            "document_type": doc_type,
            "entry_count": records.get("entry_count"),
            "entries": records["entries"][:120],
            "text_parts": records["texts"][:120],
            "text_items": records["texts"][:120],
            "artifact_records": records["artifacts"][:120],
            "embedded_artifacts_durable": True,
            "errors": records["errors"][:40],
        },
        flag_candidates=flags,
        artifacts=artifacts,
    )


def _positive_int(value: object, default: int) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


def _safe_stem(path: str) -> str:
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0] or "artifact"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *,
    source_path: str,
    requested_output_dir: str,
    files_root: str,
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return (
        '"$CTF_FILES_ROOT/.autopentest_artifacts/office_inspect_'
        f'{_safe_stem(source_path)}{suffix}_$$"'
    )


def _parse_records(stdout: str) -> dict[str, Any]:
    records: dict[str, Any] = {
        "doc_type": "",
        "entry_count": None,
        "entries": [],
        "texts": [],
        "artifacts": [],
        "errors": [],
    }
    for line in stdout.splitlines():
        parts = line.split("\t")
        if not parts:
            continue
        marker = parts[0]
        if marker == _DOC_MARKER and len(parts) >= 3:
            records["doc_type"] = parts[1]
            records["entry_count"] = _int_or_none(parts[2])
        elif marker == _ENTRY_MARKER and len(parts) >= 5:
            records["entries"].append({
                "name": parts[1],
                "size": _int_or_none(parts[2]),
                "compressed_size": _int_or_none(parts[3]),
                "role": parts[4],
            })
        elif marker == _TEXT_MARKER and len(parts) >= 4:
            records["texts"].append({
                "name": parts[1],
                "role": parts[2],
                "text": parts[3],
            })
        elif marker == _ARTIFACT_MARKER and len(parts) >= 5:
            records["artifacts"].append({
                "path": parts[1],
                "size": _int_or_none(parts[2]),
                "role": parts[3],
                "source_entry": parts[4],
                "digest": parts[5] if len(parts) >= 6 else None,
            })
        elif marker == _ERROR_MARKER and len(parts) >= 3:
            records["errors"].append({
                "stage": parts[1],
                "detail": parts[2],
            })
    return records


def _literal_flag_candidates(
    text_records: list[dict[str, object]],
    source_path: str,
) -> list[FlagCandidate]:
    flags: list[FlagCandidate] = []
    seen: set[str] = set()
    for record in text_records:
        text = str(record.get("text") or "")
        for match in FLAG_PATTERN.findall(text):
            if match in seen or not plausible_flag(match):
                continue
            seen.add(match)
            flags.append(
                FlagCandidate(
                    value=match,
                    source="office_inspect",
                    confidence=0.7,
                    metadata={
                        "literal_match": True,
                        "source_file": source_path,
                        "zip_part": str(record.get("name") or ""),
                        "office_role": str(record.get("role") or ""),
                    },
                )
            )
    return flags


def _int_or_none(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _artifact_kind(path: str, role: object) -> str:
    role_text = str(role or "").lower()
    if role_text in {"media", "embedding"}:
        prefix = role_text
    else:
        prefix = "artifact"
    ext = path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
    if ext in {"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff"}:
        return f"{prefix}_image"
    if ext in {"mp4", "mov", "avi", "mkv", "mp3", "wav"}:
        return f"{prefix}_media"
    if ext in {"zip", "pptx", "docx", "xlsx", "pdf"}:
        return f"{prefix}_container"
    return f"{prefix}_{ext or 'file'}"


__all__ = [
    "OfficeInspectPlugin",
    "_ARTIFACT_MARKER",
    "_DOC_MARKER",
    "_ENTRY_MARKER",
    "_ERROR_MARKER",
    "_SUMMARY_MARKER",
    "_TEXT_MARKER",
    "build_output",
]
