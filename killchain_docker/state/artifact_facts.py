"""Content-derived artifact facts used by planners and routing policy.

The goal of this module is locality: callers should not parse filenames,
extensions, or tool-specific kind strings.  They consume a small set of facts
derived from file(1)-style metadata, MIME types, and structured artifact
metadata.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_GENERATED_SOURCES = frozenset(
    {
        "artifact_triage_archive",
        "artifact_triage_png",
        "disk_extract",
        "foremost",
        "media_scan",
        "office_inspect",
        "png_inspect",
        "script_exec",
    }
)
_TERMINAL_SOURCES = frozenset(
    {
        "artifact_triage",
        "exiftool",
        "file",
        "strings",
    }
)
_LOW_SIGNAL_ROLES = frozenset(
    {
        "font",
        "low_signal",
        "os_metadata",
        "thumbnail",
    }
)


@dataclass(frozen=True)
class ArtifactFacts:
    """Normalized facts about an artifact, independent of its filename."""

    path: str
    source: str
    file_type: str
    mime_type: str
    role: str
    signals: frozenset[str] = field(default_factory=frozenset)
    generated: bool = False
    terminal_source: bool = False
    has_content_identity: bool = False
    has_interesting_strings: bool = False
    has_signatures: bool = False
    is_png: bool = False
    is_media: bool = False
    is_embedded_media: bool = False
    is_office_document: bool = False
    is_container: bool = False
    is_disk_image: bool = False
    is_database: bool = False
    is_text: bool = False
    is_low_signal: bool = False


def facts_from_artifact(artifact: Any) -> ArtifactFacts:
    """Build :class:`ArtifactFacts` from durable artifact metadata."""

    metadata = getattr(artifact, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}
    path = str(getattr(artifact, "path", "") or "").strip()
    source = _normalized(getattr(artifact, "source", ""))
    kind = _normalized(getattr(artifact, "kind", ""))
    kind_signal = _producer_neutral_kind(kind, source)
    file_type = _metadata_text(metadata, "file_type", "detected_type", "type")
    mime_type = _metadata_text(metadata, "mime_type", "content_type", "media_type")
    role = _metadata_text(metadata, "office_role", "role", "artifact_role")

    content_text = " ".join(part for part in (file_type, mime_type) if part)
    semantic_text = " ".join(part for part in (content_text, role, kind_signal) if part)
    mime = mime_type.strip()
    has_content_identity = bool(file_type or mime_type or metadata.get("magic"))

    signals = _signals_from_metadata(metadata)
    is_png = (
        mime == "image/png"
        or "image/png" in mime
        or "png image" in file_type
        or "portable network graphics" in file_type
    )
    is_media = (
        mime.startswith(("image/", "video/", "audio/"))
        or any(
            token in content_text
            for token in (
                "audio",
                "bitmap image",
                "gif image",
                "image data",
                "jpeg image",
                "media",
                "mpeg",
                "quicktime",
                "riff",
                "video",
                "wave audio",
            )
        )
        or any(token in kind_signal for token in ("image", "media", "video", "audio"))
    )
    is_office_document = (
        "officedocument" in mime
        or "openxmlformats" in mime
        or any(
            token in semantic_text
            for token in (
                "composite document file",
                "excel",
                "microsoft office",
                "microsoft powerpoint",
                "microsoft word",
                "office document",
                "openxml",
                "powerpoint",
                "presentation",
                "spreadsheet",
                "wordprocessing",
            )
        )
    )
    is_container = (
        mime
        in {
            "application/gzip",
            "application/java-archive",
            "application/vnd.android.package-archive",
            "application/x-7z-compressed",
            "application/x-bzip2",
            "application/x-compress",
            "application/x-cpio",
            "application/x-rar",
            "application/x-tar",
            "application/x-xz",
            "application/zip",
        }
        or any(
            token in content_text
            for token in (
                "archive data",
                "compressed data",
                "cpio archive",
                "gzip compressed",
                "rar archive",
                "tar archive",
                "zip archive",
            )
        )
        or any(token in kind_signal for token in ("archive", "compressed", "container"))
    )
    is_disk_image = any(
        token in content_text
        for token in (
            "boot sector",
            "ext2 filesystem",
            "ext3 filesystem",
            "ext4 filesystem",
            "fat",
            "filesystem image",
            "iso 9660",
            "ntfs",
            "partition table",
            "udf filesystem",
        )
    ) or _kind_indicates_disk_image(kind_signal)
    is_database = (
        mime in {"application/vnd.sqlite3", "application/x-sqlite3"}
        or any(token in content_text for token in ("database", "sqlite"))
        or "database" in kind_signal
    )
    is_text = (
        mime.startswith("text/")
        or any(
            token in content_text
            for token in (
                "ascii text",
                "csv text",
                "json data",
                "text",
                "unicode text",
                "xml",
            )
        )
        or kind_signal == "text"
    )
    is_embedded_media = source == "office_inspect" and (role == "media" or is_media)
    is_low_signal = (
        _metadata_bool(metadata, "low_signal")
        or role in _LOW_SIGNAL_ROLES
        or "font" in mime
        or any(
            token in semantic_text
            for token in (
                "font",
                "opentype",
                "truetype",
                "typeface",
                "web open font format",
            )
        )
    )

    return ArtifactFacts(
        path=path,
        source=source,
        file_type=file_type,
        mime_type=mime_type,
        role=role,
        signals=signals,
        generated=source in _GENERATED_SOURCES or "/.autopentest_artifacts/" in path,
        terminal_source=source in _TERMINAL_SOURCES,
        has_content_identity=has_content_identity,
        has_interesting_strings=_has_nonempty_sequence(
            metadata.get("interesting_strings")
        ),
        has_signatures=_has_signatures(metadata),
        is_png=is_png,
        is_media=is_media,
        is_embedded_media=is_embedded_media,
        is_office_document=is_office_document,
        is_container=is_container,
        is_disk_image=is_disk_image,
        is_database=is_database,
        is_text=is_text,
        is_low_signal=is_low_signal,
    )


def artifact_followup_priority(artifact: Any) -> int:
    """Return a deterministic priority from artifact facts."""

    facts = facts_from_artifact(artifact)
    if facts.is_low_signal or not facts.path:
        return 0
    if facts.is_office_document:
        return 100
    if facts.is_disk_image:
        return 95
    if facts.is_container:
        return 90
    if facts.is_png:
        return 85
    if facts.is_media:
        return 75
    if facts.is_database:
        return 65
    if facts.has_interesting_strings:
        return 60
    if facts.is_text:
        return 55
    if facts.has_signatures:
        return 50
    return 0


def artifact_followup_capability(artifact: Any) -> str:
    """Choose the deterministic follow-up capability for an artifact."""

    facts = facts_from_artifact(artifact)
    if facts.is_office_document:
        return "office.inspect"
    if facts.is_embedded_media and facts.is_media:
        return "media.scan"
    if facts.is_png:
        return "png.inspect"
    if facts.is_media:
        return "media.scan"
    return "artifact.triage"


def _metadata_text(metadata: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            return _normalized(value)
    return ""


def _normalized(value: Any) -> str:
    return str(value or "").strip().lower()


def _producer_neutral_kind(kind: str, source: str) -> str:
    """Return kind text without the producing tool prefix."""

    text = str(kind or "").strip().lower()
    producer = str(source or "").strip().lower()
    if producer:
        prefixes = {
            producer,
            producer.replace("-", "_").replace(" ", "_"),
            producer.replace("_", "-").replace(" ", "-"),
        }
        for prefix in sorted(prefixes, key=len, reverse=True):
            if text == prefix:
                text = ""
                break
            if text.startswith(f"{prefix}_") or text.startswith(f"{prefix}-"):
                text = text[len(prefix) + 1 :]
                break
    return text.replace("_", " ").replace("-", " ").strip()


def _kind_indicates_disk_image(kind_signal: str) -> bool:
    text = str(kind_signal or "").strip().lower()
    if not text:
        return False
    tokens = set(text.split())
    return (
        text in {"disk image", "diskimage", "filesystem image", "partition image"}
        or {"disk", "image"}.issubset(tokens)
        or {"filesystem", "image"}.issubset(tokens)
        or {"partition", "image"}.issubset(tokens)
    )


def _signals_from_metadata(metadata: dict[str, Any]) -> frozenset[str]:
    raw = metadata.get("signals") or metadata.get("content_signals") or []
    values = raw if isinstance(raw, (list, tuple, set, frozenset)) else [raw]
    return frozenset(str(item).strip().lower() for item in values if str(item).strip())


def _metadata_bool(metadata: dict[str, Any], key: str) -> bool:
    value = metadata.get(key)
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _has_nonempty_sequence(value: Any) -> bool:
    return isinstance(value, (list, tuple, set, frozenset)) and bool(value)


def _has_signatures(metadata: dict[str, Any]) -> bool:
    for key in ("signature_count", "signatures", "signature_matches"):
        value = metadata.get(key)
        if _has_nonempty_sequence(value):
            return True
        try:
            if int(str(value)) > 0:
                return True
        except (TypeError, ValueError):
            pass
    return False


__all__ = [
    "ArtifactFacts",
    "artifact_followup_capability",
    "artifact_followup_priority",
    "facts_from_artifact",
]
