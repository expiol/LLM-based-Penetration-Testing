"""Archive inspection tool."""

from __future__ import annotations

import json

from killchain_docker.tools.core import ToolExecutionRequest
from killchain_docker.tools.plugins._shared import SHARED_FILE_TARGETS_SNIPPET

TOOL_NAME = "archive_triage"

SCRIPT = r"""
import gzip
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

payload = json.loads(sys.argv[1])
files_root = Path(payload.get("files_root") or "/home/ctfplayer/ctf_files")
archive_files = payload.get("archive_files") or []
max_files = int(payload.get("max_files", 8))

records = []
archive_members = {}
interesting_members = []
flag_candidates = []
source_like_members = []
database_like_members = []
pcap_like_members = []
qualified_source_like_members = []
qualified_database_like_members = []
qualified_pcap_like_members = []
inspected = []

flag_re = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")
text_suffixes = {
    ".cfg", ".csv", ".htm", ".html", ".ini", ".json", ".md", ".php", ".py",
    ".rs", ".sh", ".sql", ".sv", ".tera", ".toml", ".txt", ".v", ".xml",
    ".yaml", ".yml", ".js",
}
source_suffixes = {
    ".c", ".cc", ".cpp", ".cxx", ".cs", ".go", ".h", ".hpp", ".htm", ".html",
    ".java", ".js", ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".sh", ".sql",
    ".sv", ".swift", ".tera", ".ts", ".tsx", ".v",
}
db_suffixes = {".db", ".sqlite", ".sqlite3"}
pcap_suffixes = {".pcap", ".pcapng", ".cap"}

def register_member(origin, member_name, sample_text=""):
    normalized = str(PurePosixPath(member_name)).lstrip("./")
    if not normalized:
        return
    qualified_name = f"{origin}:{normalized}"
    archive_members.setdefault(origin, [])
    if normalized not in archive_members[origin]:
        archive_members[origin].append(normalized)

    suffix = Path(normalized).suffix.lower()
    if suffix in source_suffixes and normalized not in source_like_members:
        source_like_members.append(normalized)
    if suffix in source_suffixes and qualified_name not in qualified_source_like_members:
        qualified_source_like_members.append(qualified_name)
    if suffix in db_suffixes and normalized not in database_like_members:
        database_like_members.append(normalized)
    if suffix in db_suffixes and qualified_name not in qualified_database_like_members:
        qualified_database_like_members.append(qualified_name)
    if suffix in pcap_suffixes and normalized not in pcap_like_members:
        pcap_like_members.append(normalized)
    if suffix in pcap_suffixes and qualified_name not in qualified_pcap_like_members:
        qualified_pcap_like_members.append(qualified_name)

    text_to_scan = normalized + "\n" + sample_text
    for flag in flag_re.findall(text_to_scan):
        if flag not in flag_candidates:
            flag_candidates.append(flag)

    lowered = sample_text.lower()
    if lowered and any(token in lowered for token in ("flag", "password", "secret", "token", "api_key", "apikey")):
        interesting_members.append(f"{origin}:{normalized}")

if not archive_files:
    records.append({"type": "summary", "text": "Archive triage failed: missing required metadata.archive_files."})
    records.append({"type": "output_context", "files_root": str(files_root), "inspected_archives": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

targets = _resolve_file_targets(files_root, archive_files, max_files=max_files, kind="archive")
target_paths = []
for target in targets:
    relpath = target["display"]
    path = Path(target["path"])
    inspected.append(relpath)
    target_paths.append((relpath, path))
    suffix = path.suffix.lower()

    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:60]:
                    if info.is_dir():
                        continue
                    sample_text = ""
                    member_suffix = Path(info.filename).suffix.lower()
                    if info.file_size <= 200000 and member_suffix in text_suffixes:
                        with zf.open(info) as fh:
                            sample_text = fh.read(4000).decode("utf-8", errors="ignore")
                    register_member(relpath, info.filename, sample_text)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                for member in tf.getmembers()[:60]:
                    if not member.isfile():
                        continue
                    sample_text = ""
                    member_suffix = Path(member.name).suffix.lower()
                    if member.size <= 200000 and member_suffix in text_suffixes:
                        extracted = tf.extractfile(member)
                        if extracted is not None:
                            sample_text = extracted.read(4000).decode("utf-8", errors="ignore")
                    register_member(relpath, member.name, sample_text)
        elif suffix == ".gz":
            sample_text = ""
            try:
                with gzip.open(path, "rb") as fh:
                    sample_text = fh.read(4000).decode("utf-8", errors="ignore")
            except Exception:
                sample_text = ""
            register_member(relpath, path.stem, sample_text)
        else:
            register_member(relpath, path.name, "")
    except Exception as exc:
        records.append({"type": "note", "text": f"Archive parse failed for {relpath}: {type(exc).__name__}: {exc}"})

extracted_files = []
for relpath, path in target_paths:
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist()[:60]:
                    if info.is_dir() or info.file_size > 50_000_000:
                        continue
                    dest = files_root / info.filename
                    if dest.exists():
                        continue
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(info) as src, open(dest, "wb") as dst:
                        dst.write(src.read())
                    extracted_files.append(info.filename)
        elif tarfile.is_tarfile(path):
            with tarfile.open(path, "r:*") as tf:
                safe_members = []
                for member in tf.getmembers()[:60]:
                    if not member.isfile() or member.size > 50_000_000:
                        continue
                    normalized = str(PurePosixPath(member.name)).lstrip("./")
                    if ".." in normalized or normalized.startswith("/"):
                        continue
                    dest = files_root / normalized
                    if dest.exists():
                        continue
                    safe_members.append(member)
                for member in safe_members:
                    normalized = str(PurePosixPath(member.name)).lstrip("./")
                    dest = files_root / normalized
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    src = tf.extractfile(member)
                    if src is not None:
                        with open(dest, "wb") as dst:
                            dst.write(src.read())
                        extracted_files.append(normalized)
    except Exception as exc:
        records.append({"type": "note", "text": f"Archive extraction failed for {relpath}: {type(exc).__name__}: {exc}"})

if extracted_files:
    records.append({"type": "note", "text": f"Extracted {len(extracted_files)} file(s) from archives to {files_root}: {extracted_files[:15]}"})

if not inspected:
    records.append({"type": "summary", "text": "Archive triage failed: no requested archive files could be read."})
    records.append({"type": "output_context", "files_root": str(files_root), "archive_files": archive_files[:max_files], "inspected_archives": [], "flag_candidates": []})
    for item in records:
        print(json.dumps(item, ensure_ascii=True))
    sys.exit(2)

member_total = sum(len(values) for values in archive_members.values())
records.append({
    "type": "summary",
    "text": (
        f"Archive triage completed for {len(inspected)} archive(s): "
        f"{member_total} embedded member(s), {len(extracted_files)} extracted to disk, "
        f"{len(flag_candidates)} flag candidate(s)."
    ),
})

records.append({
    "type": "finding",
    "finding_id": "finding-archive-triage",
    "title": "Bundled archives reviewed",
    "severity": "info",
    "description": f"Reviewed {len(inspected)} archive artifact(s) and enumerated {member_total} embedded member(s).",
    "asset_refs": ["challenge-files"],
    "evidence_refs": inspected[:5],
    "metadata": {"source": "archive_triage", "archive_members": {key: value[:20] for key, value in archive_members.items()}},
})

if source_like_members:
    records.append({
        "type": "finding",
        "finding_id": "finding-archive-sources",
        "title": "Source-like files found inside archives",
        "severity": "medium",
        "description": f"Discovered {len(source_like_members)} source-like file(s) inside bundled archives.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": qualified_source_like_members[:8],
        "metadata": {
            "source": "archive_triage",
            "source_like_members": source_like_members[:20],
            "qualified_source_like_members": qualified_source_like_members[:20],
        },
    })

if database_like_members or pcap_like_members:
    records.append({
        "type": "finding",
        "finding_id": "finding-archive-data-artifacts",
        "title": "Data artifacts found inside archives",
        "severity": "medium",
        "description": (
            f"Discovered {len(database_like_members)} database-like file(s) and "
            f"{len(pcap_like_members)} pcap-like file(s) inside bundled archives."
        ),
        "asset_refs": ["challenge-files"],
        "evidence_refs": (qualified_database_like_members + qualified_pcap_like_members)[:8],
        "metadata": {
            "source": "archive_triage",
            "database_like_members": database_like_members[:20],
            "pcap_like_members": pcap_like_members[:20],
            "qualified_database_like_members": qualified_database_like_members[:20],
            "qualified_pcap_like_members": qualified_pcap_like_members[:20],
        },
    })

if flag_candidates:
    records.append({
        "type": "finding",
        "finding_id": "finding-archive-flags",
        "title": "Flag-like token found inside archive content",
        "severity": "high",
        "description": f"Recovered {len(flag_candidates)} flag candidate(s) from bundled archive content.",
        "asset_refs": ["challenge-files"],
        "evidence_refs": flag_candidates[:5],
        "metadata": {"source": "archive_triage", "flag_candidates": flag_candidates[:10]},
    })

if interesting_members:
    records.append({"type": "note", "text": f"Interesting archive members: {interesting_members[:12]}"})

records.append({
    "type": "output_context",
    "files_root": str(files_root),
    "inspected_archives": inspected,
    "archive_members": {key: value[:30] for key, value in archive_members.items()},
    "source_like_members": source_like_members[:20],
    "database_like_members": database_like_members[:20],
    "pcap_like_members": pcap_like_members[:20],
    "qualified_source_like_members": qualified_source_like_members[:20],
    "qualified_database_like_members": qualified_database_like_members[:20],
    "qualified_pcap_like_members": qualified_pcap_like_members[:20],
    "flag_candidates": flag_candidates[:10],
    "extracted_files": extracted_files[:30],
    "manual_checks": [
        "Review embedded archive members for hidden source, database, or capture files.",
        "Inspect archive member names for alternate challenge stages or backup files.",
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
        "archive_files": request.metadata.get("archive_files", []),
        "max_files": request.metadata.get("max_files", 8),
    }
    return ["-c", SCRIPT, json.dumps(payload)]
