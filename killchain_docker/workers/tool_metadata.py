"""Normalize worker-selected metadata before invoking concrete tool plugins."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse

from killchain_docker.state import RunState, TodoItem
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools.core import _first_string, _strings

_FILE_CONTRACTS: dict[ToolCapability, str] = {
    ToolCapability.ARTIFACT_SOURCE: "source_files",
    ToolCapability.ARTIFACT_PCAP: "pcap_files",
    ToolCapability.ARTIFACT_BINARY_TRIAGE: "binary_files",
    ToolCapability.ARTIFACT_BINARY_DISASSEMBLE: "binary_files",
    ToolCapability.ARTIFACT_BINARY_EXECUTE: "binary_files",
    ToolCapability.ARTIFACT_ARCHIVE: "archive_files",
    ToolCapability.ARTIFACT_SQLITE: "database_files",
    ToolCapability.ARTIFACT_REPO: "repo_paths",
}

_BASE_FILE_CAPABILITIES = {
    ToolCapability.ARTIFACT_TRIAGE,
    ToolCapability.ARTIFACT_ARCHIVE,
    ToolCapability.ARTIFACT_SOURCE,
    ToolCapability.ARTIFACT_RUNTIME,
    ToolCapability.ARTIFACT_COMPUTATION,
    ToolCapability.ARTIFACT_BINARY_TRIAGE,
    ToolCapability.ARTIFACT_BINARY_DISASSEMBLE,
    ToolCapability.ARTIFACT_BINARY_EXECUTE,
    ToolCapability.ARTIFACT_SQLITE,
    ToolCapability.ARTIFACT_PCAP,
    ToolCapability.ARTIFACT_REPO,
    ToolCapability.FLAG_HARVEST,
    ToolCapability.SCRIPT_EXECUTE,
}


def tool_metadata_contract(capability: ToolCapability | str) -> dict[str, object]:
    """Return the concise metadata contract shown to tool-selecting workers."""

    cap = ToolCapability(capability)
    common_file = {
        "optional": ["files_root", "challenge_files", "max_files"],
        "notes": "Use paths relative to files_root where possible.",
    }
    if cap == ToolCapability.SCRIPT_EXECUTE:
        return {
            "required": ["script_code"],
            "optional": [
                "script_language",
                "files_root",
                "challenge_files",
                "timeout_s",
                "flag_format",
            ],
            "notes": (
                "Put self-contained executable source in script_code. "
                "Do not rely on /tmp files written by earlier todos; read challenge files "
                "or regenerate diagnostics inside this script and print useful stdout. "
                "Two env vars are exported when challenge_files are listed: "
                "CTF_FILES_ROOT (read-only originals; protected by chmod) and "
                "CTF_WRITABLE_FILES_ROOT (pre-populated mutable copies of every "
                "challenge_files entry). Open files under CTF_WRITABLE_FILES_ROOT "
                "for any in-place mutation. Do NOT use shutil.copy2 on the "
                "originals; copy2 preserves the read-only mode bits and the "
                "subsequent open(..., 'wb') will raise PermissionError."
            ),
        }
    if cap in _FILE_CONTRACTS:
        field_name = _FILE_CONTRACTS[cap]
        return {
            "required": [field_name],
            **common_file,
        }
    if cap == ToolCapability.ARTIFACT_TRIAGE:
        return {"required": [], **common_file}
    if cap in {ToolCapability.ARTIFACT_RUNTIME, ToolCapability.ARTIFACT_COMPUTATION}:
        return {"required": ["source_files"], **common_file}
    if cap == ToolCapability.HTTP_METADATA:
        return {"required": ["base_url or hostname"], "optional": ["asset_id", "ports"]}
    if cap == ToolCapability.HTTP_CONTENT:
        return {"required": ["base_url"], "optional": ["asset_id", "paths"]}
    if cap == ToolCapability.HTTP_PROBE_PATHS:
        return {"required": ["base_url"], "optional": ["asset_id", "paths"]}
    if cap == ToolCapability.HTTP_FORM_PROBE:
        return {
            "required": ["page_url"],
            "optional": ["asset_id", "forms", "text_payloads", "filename_variants", "query_variants"],
        }
    if cap == ToolCapability.HOST_INVENTORY:
        return {"required": ["hostname"], "optional": ["asset_id", "ports"]}
    if cap == ToolCapability.HOST_BANNER:
        return {"required": ["hostname"], "optional": ["asset_id", "ports"]}
    if cap == ToolCapability.VULN_SCAN:
        return {"required": ["target"], "optional": ["asset_id", "base_url", "hostname"]}
    if cap == ToolCapability.EXPLOIT_PROBE:
        return {
            "required": ["base_url or hostname"],
            "optional": ["asset_id", "ports", "http_paths", "tcp_inputs", "candidate_credentials"],
        }
    if cap == ToolCapability.CREDENTIAL_LOGIN:
        return {"required": ["base_url"], "optional": ["asset_id", "candidate_credentials", "seed_paths"]}
    if cap == ToolCapability.FLAG_HARVEST:
        return {"required": [], "optional": ["files_root", "seed_terms", "max_files"]}
    return {"required": [], "optional": []}


def normalize_tool_metadata(
    capability: ToolCapability | str,
    todo: TodoItem,
    state: RunState,
    selected_metadata: dict[str, object],
) -> dict[str, object]:
    """Return clean plugin metadata for one capability or raise a precise error."""

    cap = ToolCapability(capability)
    raw: dict[str, object] = {**selected_metadata, **todo.context}
    clean: dict[str, object] = {}

    if cap in _BASE_FILE_CAPABILITIES:
        clean["files_root"] = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
        challenge_files = _strings(raw.get("challenge_files")) or _challenge_files(state)
        if challenge_files:
            clean["challenge_files"] = [
                _normalize_file_ref(item, str(clean["files_root"]))
                for item in challenge_files
            ]
        if "max_files" in raw:
            clean["max_files"] = raw["max_files"]

    if cap == ToolCapability.SCRIPT_EXECUTE:
        _normalize_script_metadata(raw, clean)
        challenge = state.metadata.get("challenge", {}) or {}
        if "flag_format" in challenge:
            clean["flag_format"] = challenge.get("flag_format") or ""
        else:
            clean.pop("flag_format", None)
        _require(clean.get("script_code"), cap, "script_code")
        return clean

    if cap in _FILE_CONTRACTS:
        field_name = _FILE_CONTRACTS[cap]
        targets = _collect_file_targets(raw, clean, field_name)
        clean[field_name] = targets
        _require(targets, cap, field_name)
        return clean

    if cap in {ToolCapability.ARTIFACT_RUNTIME, ToolCapability.ARTIFACT_COMPUTATION}:
        targets = _collect_file_targets(raw, clean, "source_files")
        clean["source_files"] = targets
        _require(targets, cap, "source_files")
        return clean

    if cap == ToolCapability.ARTIFACT_TRIAGE:
        return clean

    if cap == ToolCapability.FLAG_HARVEST:
        if "seed_terms" in raw:
            clean["seed_terms"] = _strings(raw.get("seed_terms"))
        if "max_files" in raw:
            clean["max_files"] = raw["max_files"]
        return clean

    return _normalize_network_metadata(cap, raw, state)


def has_script_metadata(metadata: dict[str, object]) -> bool:
    return bool(_first_string(metadata.get("script_code")))


def has_network_target(metadata: dict[str, object], state: RunState | None = None) -> bool:
    if any(_first_string(metadata.get(key)) for key in ("base_url", "hostname", "target", "scope")):
        return True
    return bool(state and state.authorized_scope)


def _normalize_script_metadata(raw: dict[str, object], clean: dict[str, object]) -> None:
    script_code = _first_string(raw.get("script_code"))
    clean["script_code"] = script_code
    clean["script_language"] = _normalize_script_language(
        _first_string(raw.get("script_language"))
        or "python"
    )
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    if "flag_format" in raw:
        clean["flag_format"] = raw["flag_format"]


def _normalize_network_metadata(
    cap: ToolCapability,
    raw: dict[str, object],
    state: RunState,
) -> dict[str, object]:
    clean: dict[str, object] = {}
    state.infer_asset_identity(raw)
    scope = _first_string(raw.get("scope")) or (state.authorized_scope[0] if state.authorized_scope else "")
    base_url = _first_string(raw.get("base_url")) or (_scope_url(scope) if scope else "")
    hostname = _first_string(raw.get("hostname")) or _hostname_from(scope or base_url or _first_string(raw.get("target")))
    target = _first_string(raw.get("target"))

    if "asset_id" in raw:
        clean["asset_id"] = raw["asset_id"]
    elif cap in {
        ToolCapability.HTTP_METADATA,
        ToolCapability.HTTP_CONTENT,
        ToolCapability.HTTP_PROBE_PATHS,
        ToolCapability.HTTP_FORM_PROBE,
        ToolCapability.HOST_INVENTORY,
        ToolCapability.HOST_BANNER,
        ToolCapability.VULN_SCAN,
        ToolCapability.EXPLOIT_PROBE,
        ToolCapability.CREDENTIAL_LOGIN,
    }:
        clean["asset_id"] = "seed-asset"

    if base_url:
        clean["base_url"] = base_url
    if hostname:
        clean["hostname"] = hostname
    if target:
        clean["target"] = target
    elif cap == ToolCapability.VULN_SCAN and base_url:
        clean["target"] = base_url
    elif cap == ToolCapability.VULN_SCAN and hostname:
        clean["target"] = hostname

    if "ports" in raw:
        clean["ports"] = raw["ports"]
    if cap in {ToolCapability.HTTP_CONTENT, ToolCapability.HTTP_PROBE_PATHS} and "paths" in raw:
        clean["paths"] = raw["paths"]
    if cap == ToolCapability.HTTP_FORM_PROBE:
        page_url = _first_string(raw.get("page_url")) or base_url
        if page_url:
            clean["page_url"] = page_url
        for key in ("forms", "text_payloads", "filename_variants", "query_variants"):
            if key in raw:
                clean[key] = raw[key]
    if cap == ToolCapability.EXPLOIT_PROBE:
        for key in ("http_paths", "tcp_inputs", "candidate_credentials"):
            if key in raw:
                clean[key] = raw[key]
    if cap == ToolCapability.CREDENTIAL_LOGIN:
        for key in ("candidate_credentials", "seed_paths"):
            if key in raw:
                clean[key] = raw[key]

    if cap in {ToolCapability.HTTP_METADATA, ToolCapability.HOST_INVENTORY, ToolCapability.HOST_BANNER}:
        _require(clean.get("base_url") or clean.get("hostname"), cap, "base_url or hostname")
    elif cap in {ToolCapability.HTTP_CONTENT, ToolCapability.HTTP_PROBE_PATHS, ToolCapability.CREDENTIAL_LOGIN}:
        _require(clean.get("base_url"), cap, "base_url")
    elif cap == ToolCapability.HTTP_FORM_PROBE:
        _require(clean.get("page_url"), cap, "page_url")
    elif cap == ToolCapability.VULN_SCAN:
        _require(clean.get("target"), cap, "target")
    elif cap == ToolCapability.EXPLOIT_PROBE:
        _require(clean.get("base_url") or clean.get("hostname"), cap, "base_url or hostname")

    return clean


def _collect_file_targets(
    raw: dict[str, object],
    clean: dict[str, object],
    field_name: str,
) -> list[str]:
    files_root = str(clean.get("files_root") or DEFAULT_FILES_ROOT)
    targets = _strings(raw.get(field_name))
    return _dedupe(_normalize_file_ref(item, files_root) for item in targets)


def _challenge_files(state: RunState) -> list[str]:
    return _strings((state.metadata.get("challenge", {}) or {}).get("files"))


def _dedupe(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def _normalize_file_ref(value: object, files_root: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    root = files_root.rstrip("/")
    if text.startswith(root + "/"):
        text = text[len(root) + 1 :]
    if text.startswith("./"):
        text = text[2:]
    return text


def _normalize_script_language(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"python3", "py"}:
        return "python"
    if lowered in {"shell", "zsh"}:
        return "bash"
    return lowered or "python"


def _hostname_from(value: str | None) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.hostname:
        return parsed.hostname
    if "://" not in text:
        return text.split(":", 1)[0]
    return ""


def _scope_url(scope: str) -> str:
    parsed = urlparse(scope)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return scope
    return ""


def _require(value: object, cap: ToolCapability, field_name: str) -> None:
    if value in (None, "", [], {}, ()):
        raise ToolExecutionError(f"{cap.value} missing required metadata.{field_name}")
