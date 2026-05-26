"""Metadata contracts for artifact inspection capabilities."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability

ARTIFACT_TOOL_METADATA_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.FILE_CMD: {
        "required": ["path"],
        "optional": [],
        "notes": "Identify file type. path is absolute or relative to ctf_files.",
    },
    ToolCapability.ARTIFACT_TRIAGE: {
        "required": [],
        "optional": ["path", "paths", "challenge_files", "files_root", "max_strings"],
        "notes": (
            "Deterministic first-pass artifact triage. Accepts one path, paths, "
            "or challenge_files; runs file/strings/metadata/signature checks and "
            "returns structured artifacts and candidates."
        ),
    },
    ToolCapability.DISK_EXTRACT: {
        "required": [],
        "optional": [
            "path",
            "file_path",
            "artifact_path",
            "challenge_files",
            "files_root",
            "output_dir",
            "max_files",
            "max_extract_mb",
            "offset",
            "offsets",
            "partition_offset",
        ],
        "notes": (
            "Deterministic bounded extraction from disk images into durable "
            "registered artifacts."
        ),
    },
    ToolCapability.OFFICE_INSPECT: {
        "required": [],
        "optional": [
            "path",
            "file_path",
            "artifact_path",
            "challenge_files",
            "files_root",
            "output_dir",
            "max_entries",
            "max_artifacts",
            "max_extract_mb",
            "max_text_chars",
        ],
        "notes": (
            "Deterministic bounded inspection for OOXML office document "
            "containers, including XML text and embedded media."
        ),
    },
    ToolCapability.MEDIA_SCAN: {
        "required": [],
        "optional": [
            "path",
            "paths",
            "file_path",
            "artifact_path",
            "challenge_files",
            "files_root",
            "max_files",
            "max_extract_mb",
        ],
        "notes": (
            "Deterministic batch inspection for embedded media files. Detects "
            "appended payloads after image EOF markers, keyword strings, simple "
            "image metadata, literal flag-like evidence, and registers extracted "
            "payload artifacts."
        ),
    },
    ToolCapability.PNG_INSPECT: {
        "required": [],
        "optional": [
            "path",
            "file_path",
            "artifact_path",
            "challenge_files",
            "files_root",
            "output_dir",
            "max_extract_mb",
            "max_lsb_bytes",
        ],
        "notes": (
            "Deterministic PNG inspection: chunks, text chunks, IDAT metadata, "
            "bounded LSB extraction, and durable extracted payloads."
        ),
    },
    ToolCapability.STRINGS_CMD: {
        "required": ["path"],
        "optional": ["min_length", "encoding"],
        "notes": "Extract printable strings. min_length default 6, encoding default 's' (single-byte).",
    },
    ToolCapability.TSHARK: {
        "required": ["path"],
        "optional": ["filter", "fields", "extra_args"],
        "notes": "PCAP analysis. filter is a display filter. fields is comma-separated field names.",
    },
    ToolCapability.EXIFTOOL: {
        "required": ["path"],
        "optional": [],
        "notes": "Extract file metadata (EXIF, XMP, etc.).",
    },
    ToolCapability.STEGHIDE: {
        "required": ["path"],
        "optional": ["passphrase", "action"],
        "notes": "Steganography. action is 'info' (default) or 'extract'. passphrase for protected files.",
    },
    ToolCapability.FOREMOST: {
        "required": ["path"],
        "optional": ["output_dir"],
        "notes": "File carving from images/binary blobs. Carved files listed in output.",
    },
    ToolCapability.SQLITE3: {
        "required": ["path"],
        "optional": ["query"],
        "notes": "SQLite query. query default '.tables'. Use SQL or dot-commands.",
    },
}
