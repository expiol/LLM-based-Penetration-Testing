"""Artifact-oriented metadata normalization."""

from __future__ import annotations

from killchain_docker.tools.core import ToolExecutionError, _first_string
from killchain_docker.workers.tooling.metadata.common import (
    files_root_from,
    first_challenge_file,
    normalize_challenge_path,
)


def normalize_artifact_triage_metadata(raw: dict[str, object]) -> dict[str, object]:
    files_root = files_root_from(raw)
    clean: dict[str, object] = {"files_root": files_root}
    paths = artifact_triage_paths(raw)
    if paths:
        clean["paths"] = [normalize_challenge_path(path, files_root) for path in paths]
    if "max_strings" in raw:
        clean["max_strings"] = raw["max_strings"]
    return clean


def artifact_triage_paths(raw: dict[str, object]) -> list[object]:
    value = raw.get("paths")
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if _first_string(item)]
    path = raw.get("path")
    if _first_string(path):
        return [path]
    value = raw.get("challenge_files")
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if _first_string(item)]
    return []


def normalize_disk_extract_metadata(raw: dict[str, object]) -> dict[str, object]:
    files_root = files_root_from(raw)
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("disk.extract missing metadata.path")
    clean: dict[str, object] = {
        "path": normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in (
        "output_dir",
        "max_files",
        "max_extract_mb",
        "offset",
        "offsets",
        "partition_offset",
    ):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def normalize_office_inspect_metadata(raw: dict[str, object]) -> dict[str, object]:
    files_root = files_root_from(raw)
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("office.inspect missing metadata.path")
    clean: dict[str, object] = {
        "path": normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in (
        "output_dir",
        "max_entries",
        "max_artifacts",
        "max_extract_mb",
        "max_text_chars",
    ):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def normalize_png_inspect_metadata(raw: dict[str, object]) -> dict[str, object]:
    files_root = files_root_from(raw)
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("png.inspect missing metadata.path")
    clean: dict[str, object] = {
        "path": normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in ("output_dir", "max_extract_mb", "max_lsb_bytes"):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def normalize_media_scan_metadata(raw: dict[str, object]) -> dict[str, object]:
    files_root = files_root_from(raw)
    paths = media_scan_paths(raw)
    if not paths:
        raise ToolExecutionError("media.scan missing metadata.path or metadata.paths")
    clean: dict[str, object] = {
        "paths": [normalize_challenge_path(path, files_root) for path in paths],
        "files_root": files_root,
    }
    if len(clean["paths"]) == 1:
        clean["path"] = clean["paths"][0]
    for key in ("max_files", "max_extract_mb"):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def media_scan_paths(raw: dict[str, object]) -> list[object]:
    value = raw.get("paths")
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if _first_string(item)]
    for key in ("path", "artifact_path", "file_path"):
        value = raw.get(key)
        if _first_string(value):
            return [value]
    value = raw.get("challenge_files")
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if _first_string(item)]
    return []
