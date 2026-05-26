"""office.inspect — deterministic inspection for OOXML/ZIP office documents."""

from __future__ import annotations
import re
import shlex
from typing import Any
from killchain_docker.state.domain import FlagCandidate
from killchain_docker.state.domain import Artifact
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.constants import FLAG_PATTERN, plausible_flag
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import _require, _run, _status
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
_OFFICE_INSPECT_PY = '\nimport os\nimport re\nimport sys\nimport hashlib\nimport zipfile\nimport xml.etree.ElementTree as ET\nfrom pathlib import Path\n\nDOC = "__KILLCHAIN_OFFICE_INSPECT_DOC__"\nENTRY = "__KILLCHAIN_OFFICE_INSPECT_ENTRY__"\nTEXT = "__KILLCHAIN_OFFICE_INSPECT_TEXT__"\nARTIFACT = "__KILLCHAIN_OFFICE_INSPECT_ARTIFACT__"\nERROR = "__KILLCHAIN_OFFICE_INSPECT_ERROR__"\nSUMMARY = "__KILLCHAIN_OFFICE_INSPECT_SUMMARY__"\n\ndef clean(value, limit=400):\n    return re.sub(r"\\s+", " ", str(value).replace("\\t", " ").replace("\\n", " ")).strip()[:limit]\n\ndef safe_part(value):\n    out = re.sub(r"[^A-Za-z0-9_.@%+=,-]+", "_", str(value).strip())\n    return out.strip("._")[:80] or "file"\n\ndef safe_relpath(value):\n    text = str(value).replace("\\\\", "/").strip().strip("/")\n    parts = []\n    for part in text.split("/"):\n        if not part or part in {".", ".."}:\n            continue\n        parts.append(safe_part(part))\n    return "/".join(parts) or "file"\n\ndef role_for(name):\n    lowered = name.lower()\n    if lowered.startswith("ppt/slides/slide") and lowered.endswith(".xml"):\n        return "slide"\n    if lowered.startswith("ppt/notesslides/notesslide") and lowered.endswith(".xml"):\n        return "notes"\n    if "comments" in lowered and lowered.endswith(".xml"):\n        return "comments"\n    if lowered in {"docprops/core.xml", "docprops/app.xml"} or "custom.xml" in lowered:\n        return "properties"\n    if lowered.endswith(".rels"):\n        return "relationship"\n    if "/media/" in lowered:\n        return "media"\n    if "/embeddings/" in lowered or "oleobject" in lowered:\n        return "embedding"\n    if lowered.endswith(".xml"):\n        return "xml"\n    return "file"\n\ndef ext_for(names):\n    lowered = {name.lower() for name in names}\n    if "[content_types].xml" in lowered and any(name.startswith("ppt/") for name in lowered):\n        return "pptx"\n    if "[content_types].xml" in lowered and any(name.startswith("word/") for name in lowered):\n        return "docx"\n    if "[content_types].xml" in lowered and any(name.startswith("xl/") for name in lowered):\n        return "xlsx"\n    return "zip"\n\ndef text_from_xml(data):\n    try:\n        root = ET.fromstring(data)\n    except ET.ParseError:\n        raw = data.decode("utf-8", "ignore")\n        raw = re.sub(r"<[^>]+>", " ", raw)\n        return clean(raw, 4000)\n    parts = [part.strip() for part in root.itertext() if part and part.strip()]\n    for element in root.iter():\n        for key, value in element.attrib.items():\n            if not value or not str(value).strip():\n                continue\n            key_name = key.rsplit("}", 1)[-1].lower()\n            if key_name in {"descr", "description", "title", "name", "tooltip", "target", "val", "value"}:\n                parts.append(str(value).strip())\n    return clean(" | ".join(parts), 4000)\n\ndef should_extract(name, info):\n    if info.is_dir():\n        return False\n    lowered = name.lower()\n    if "/media/" in lowered or "/embeddings/" in lowered:\n        return True\n    if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".mp4", ".mov", ".avi", ".wav", ".mp3", ".pdf", ".zip", ".bin")):\n        return True\n    return False\n\ndef main():\n    src = Path(sys.argv[1])\n    out_root = Path(sys.argv[2])\n    max_entries = int(sys.argv[3])\n    max_artifacts = int(sys.argv[4])\n    max_bytes = int(sys.argv[5]) * 1024 * 1024\n    max_text = int(sys.argv[6])\n    out_root.mkdir(parents=True, exist_ok=True)\n\n    try:\n        zf = zipfile.ZipFile(src)\n    except (OSError, zipfile.BadZipFile) as exc:\n        print(f"{ERROR}\\topen\\t{clean(exc)}")\n        print(f"{SUMMARY}\\t0\\t0\\t0\\t0")\n        return\n\n    with zf:\n        infos = zf.infolist()\n        names = [info.filename for info in infos]\n        doc_type = ext_for(names)\n        print(f"{DOC}\\t{doc_type}\\t{len(infos)}")\n        text_count = 0\n        artifact_count = 0\n        artifact_bytes = 0\n        errors = 0\n        for info in infos[:max_entries]:\n            name = info.filename\n            role = role_for(name)\n            print(f"{ENTRY}\\t{clean(name)}\\t{info.file_size}\\t{info.compress_size}\\t{role}")\n            lowered = name.lower()\n            if lowered.endswith((".xml", ".rels")) and info.file_size <= 4 * 1024 * 1024:\n                try:\n                    data = zf.read(info)\n                except Exception as exc:\n                    errors += 1\n                    print(f"{ERROR}\\tread\\t{clean(name)}: {clean(exc)}")\n                else:\n                    text = text_from_xml(data)\n                    if text:\n                        print(f"{TEXT}\\t{clean(name)}\\t{role}\\t{clean(text, max_text)}")\n                        text_count += 1\n            if should_extract(name, info):\n                if artifact_count >= max_artifacts:\n                    continue\n                if info.file_size <= 0 or artifact_bytes + info.file_size > max_bytes:\n                    continue\n                try:\n                    data = zf.read(info)\n                except Exception as exc:\n                    errors += 1\n                    print(f"{ERROR}\\tread\\t{clean(name)}: {clean(exc)}")\n                    continue\n                dest = out_root / safe_relpath(name)\n                dest.parent.mkdir(parents=True, exist_ok=True)\n                dest.write_bytes(data)\n                digest = hashlib.sha256(data).hexdigest()\n                artifact_count += 1\n                artifact_bytes += len(data)\n                print(f"{ARTIFACT}\\t{dest}\\t{len(data)}\\t{role}\\t{clean(name)}\\t{digest}")\n        print(f"{SUMMARY}\\t{len(infos)}\\t{text_count}\\t{artifact_count}\\t{errors}")\n\nif __name__ == "__main__":\n    main()\n'


class OfficeInspectPlugin:
    name = "office_inspect"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        files_root = str(request.metadata.get("files_root") or DEFAULT_FILES_ROOT)
        output_dir = str(request.metadata.get("output_dir") or "").strip()
        max_entries = _positive_int(
            request.metadata.get("max_entries"), _DEFAULT_MAX_ENTRIES
        )
        max_artifacts = _positive_int(
            request.metadata.get("max_artifacts"), _DEFAULT_MAX_ARTIFACTS
        )
        max_extract_mb = _positive_int(
            request.metadata.get("max_extract_mb"), _DEFAULT_MAX_EXTRACT_MB
        )
        max_text_chars = _positive_int(
            request.metadata.get("max_text_chars"), _DEFAULT_MAX_TEXT_CHARS
        )
        output_expr = _durable_output_expr(
            source_path=path, requested_output_dir=output_dir, files_root=files_root
        )
        cmd = f'_kc_src={shlex.quote(path)}; _kc_out={output_expr}; python3 -c {shlex.quote(_OFFICE_INSPECT_PY)} "$_kc_src" "$_kc_out" {max_entries} {max_artifacts} {max_extract_mb} {max_text_chars}'
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
    summary = f"office.inspect {source_path}: {doc_type}, {len(records['texts'])} text part(s), {len(records['artifacts'])} embedded artifact(s)"
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
    return re.sub("[^A-Za-z0-9_.-]+", "_", stem)[:48] or "artifact"


def _durable_output_expr(
    *, source_path: str, requested_output_dir: str, files_root: str
) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    durable_root = f"{root}/.autopentest_artifacts"
    requested = requested_output_dir.strip()
    if requested and (
        requested == durable_root or requested.startswith(f"{durable_root}/")
    ):
        return shlex.quote(requested)
    suffix = f"_{_safe_stem(requested)}" if requested else ""
    return f'"$CTF_FILES_ROOT/.autopentest_artifacts/office_inspect_{_safe_stem(source_path)}{suffix}_$$"'


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
            records["entries"].append(
                {
                    "name": parts[1],
                    "size": _int_or_none(parts[2]),
                    "compressed_size": _int_or_none(parts[3]),
                    "role": parts[4],
                }
            )
        elif marker == _TEXT_MARKER and len(parts) >= 4:
            records["texts"].append(
                {"name": parts[1], "role": parts[2], "text": parts[3]}
            )
        elif marker == _ARTIFACT_MARKER and len(parts) >= 5:
            records["artifacts"].append(
                {
                    "path": parts[1],
                    "size": _int_or_none(parts[2]),
                    "role": parts[3],
                    "source_entry": parts[4],
                    "digest": parts[5] if len(parts) >= 6 else None,
                }
            )
        elif marker == _ERROR_MARKER and len(parts) >= 3:
            records["errors"].append({"stage": parts[1], "detail": parts[2]})
    return records


def _literal_flag_candidates(
    text_records: list[dict[str, object]], source_path: str
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
