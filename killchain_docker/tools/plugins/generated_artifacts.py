"""Shared parsing for tool-generated durable artifact manifests."""

from __future__ import annotations
from killchain_docker.state.domain import Artifact

ARTIFACTS_START = "__KILLCHAIN_SCRIPT_ARTIFACTS__"
ARTIFACTS_END = "__KILLCHAIN_SCRIPT_ARTIFACTS_END__"


def artifact_records_from_stdout(
    stdout: str, *, limit: int = 40
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    in_section = False
    for line in stdout.splitlines():
        if line.strip() == ARTIFACTS_START:
            in_section = True
            continue
        if line.strip() == ARTIFACTS_END:
            break
        if not in_section:
            continue
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        path, size_text, origin, relative_path = parts[:4]
        if not path.startswith("/"):
            continue
        try:
            size = int(size_text)
        except ValueError:
            size = None
        digest = parts[4].strip() if len(parts) >= 5 else ""
        file_type = parts[5].strip() if len(parts) >= 6 else ""
        mime_type = parts[6].strip() if len(parts) >= 7 else ""
        records.append(
            {
                "path": path,
                "size": size,
                "origin": origin,
                "relative_path": relative_path,
                "digest": digest or None,
                "file_type": file_type or None,
                "mime_type": mime_type or None,
            }
        )
        if len(records) >= limit:
            break
    return records


def artifacts_from_records(
    records: list[dict[str, object]], *, source: str, kind_prefix: str, limit: int = 40
) -> list[Artifact]:
    artifacts: list[Artifact] = []
    for record in records[:limit]:
        path = str(record.get("path") or "")
        if not path:
            continue
        size = record.get("size")
        file_type = str(record.get("file_type") or "")
        mime_type = str(record.get("mime_type") or "")
        digest = record.get("digest")
        artifacts.append(
            Artifact(
                path=path,
                kind=artifact_kind(
                    file_type=file_type, mime_type=mime_type, prefix=kind_prefix
                ),
                source=source,
                size=size if isinstance(size, int) else None,
                digest=str(digest) if digest else None,
                metadata={
                    "origin": record.get("origin"),
                    "relative_path": record.get("relative_path"),
                    "file_type": file_type or None,
                    "mime_type": mime_type or None,
                },
            )
        )
    return artifacts


def artifact_kind(*, file_type: str = "", mime_type: str = "", prefix: str) -> str:
    text = " ".join([file_type.lower(), mime_type.lower()])
    if "image/png" in text or "png image" in text:
        return f"{prefix}_png"
    if "image/jpeg" in text or "jpeg image" in text:
        return f"{prefix}_jpeg"
    if "image/gif" in text or "gif image" in text:
        return f"{prefix}_gif"
    if "zip" in text or "archive" in text:
        return f"{prefix}_archive"
    if "sqlite" in text or "database" in text:
        return f"{prefix}_database"
    if "text/" in text or "ascii text" in text or "unicode text" in text:
        return f"{prefix}_text"
    return prefix
