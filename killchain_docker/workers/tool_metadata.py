"""Normalize worker-selected metadata before invoking tool plugins.

Each capability has a contract (required/optional fields + usage notes)
and a normalize function that validates & cleans metadata before dispatch.
"""

from __future__ import annotations

from killchain_docker.state import RunState, TodoItem
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools.core import _first_string


# ---------------------------------------------------------------------------
# Metadata contracts — shown to the LLM during tool selection
# ---------------------------------------------------------------------------

_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.SHELL_EXEC: {
        "required": ["command"],
        "optional": ["timeout_s"],
        "notes": "Free-form bash -c. Use any installed tool with pipes/redirects.",
    },
    ToolCapability.SCRIPT_EXEC: {
        "required": ["script_code"],
        "optional": ["script_language", "files_root", "timeout_s"],
        "notes": "Write self-contained source. Default python. Supported: python, bash, sh, javascript, ruby, perl.",
    },
    ToolCapability.NMAP: {
        "required": ["target"],
        "optional": ["ports", "scan_type", "extra_args"],
        "notes": "Port scanning. scan_type default '-sV'. ports e.g. '1-1000' or '80,443,8080'.",
    },
    ToolCapability.CURL: {
        "required": ["url"],
        "optional": [
            "method", "headers", "data", "extra_args",
            "session_id", "cookies", "follow_redirects", "auth",
        ],
        "notes": (
            "HTTP request. method default 'GET'. headers is a dict. data is string body. "
            "session_id enables cookie jar persistence across requests (same id = same cookies). "
            "cookies is a string 'k1=v1; k2=v2' for one-shot cookies. "
            "follow_redirects=true adds -L. auth is 'user:pass' for HTTP basic auth."
        ),
    },
    ToolCapability.SQLMAP: {
        "required": ["url"],
        "optional": [
            "extra_args", "cookie", "session_id", "headers", "data", "method",
        ],
        "notes": (
            "SQL injection scan. Runs --batch --level=3 --risk=2 by default. "
            "cookie is 'k=v; k2=v2' for authenticated testing. "
            "session_id reuses cookie jar from a prior curl session. "
            "headers is a dict. data is POST body string. method forces HTTP verb."
        ),
    },
    ToolCapability.NIKTO: {
        "required": ["target"],
        "optional": ["extra_args", "cookie", "session_id", "tuning"],
        "notes": (
            "Web vulnerability scan. target is a URL or host:port. "
            "cookie is 'k=v; k2=v2' for authenticated scanning. "
            "session_id reuses cookie jar from a prior curl session. "
            "tuning selects scan categories (e.g. '1' info disclosure, '2' misconfiguration)."
        ),
    },
    ToolCapability.FILE_CMD: {
        "required": ["path"],
        "optional": [],
        "notes": "Identify file type. path is absolute or relative to ctf_files.",
    },
    ToolCapability.STRINGS_CMD: {
        "required": ["path"],
        "optional": ["min_length", "encoding"],
        "notes": "Extract printable strings. min_length default 6, encoding default 's' (single-byte).",
    },
    ToolCapability.BINWALK: {
        "required": ["path"],
        "optional": ["extract"],
        "notes": "Firmware/binary analysis. Set extract=true to carve embedded files.",
    },
    ToolCapability.RADARE2: {
        "required": ["path"],
        "optional": ["commands"],
        "notes": "Binary analysis with r2. commands default 'aaa; afl; pdf @ main'. Use r2 command syntax.",
    },
    ToolCapability.OBJDUMP: {
        "required": ["path"],
        "optional": ["flags"],
        "notes": "Disassembly. flags default '-d -M intel'.",
    },
    ToolCapability.GDB: {
        "required": ["path"],
        "optional": ["commands"],
        "notes": "Debugging. commands piped to gdb -batch. e.g. 'info functions' or 'break main\\nrun\\nbt'.",
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
    ToolCapability.JOHN: {
        "required": ["path"],
        "optional": ["wordlist", "format", "extra_args"],
        "notes": "Password cracking. path is a hash file. Cracked results shown via --show.",
    },
    ToolCapability.FCRACKZIP: {
        "required": ["path"],
        "optional": ["wordlist", "extra_args"],
        "notes": "ZIP password cracking. wordlist default rockyou.txt.",
    },
    ToolCapability.JADX: {
        "required": ["path"],
        "optional": ["output_dir"],
        "notes": "APK/DEX decompilation. Outputs Java source files.",
    },
}


def tool_metadata_contract(capability: ToolCapability | str) -> dict[str, object]:
    """Return the metadata contract for a capability."""
    cap = ToolCapability(capability)
    return _CONTRACTS.get(cap, {"required": [], "optional": []})


# ---------------------------------------------------------------------------
# Metadata normalization
# ---------------------------------------------------------------------------

def normalize_tool_metadata(
    capability: ToolCapability | str,
    todo: TodoItem,
    state: RunState,
    selected_metadata: dict[str, object],
) -> dict[str, object]:
    """Validate and clean metadata before dispatching to a plugin."""

    cap = ToolCapability(capability)
    raw: dict[str, object] = {**selected_metadata, **todo.context}
    contract = _CONTRACTS.get(cap)
    if not contract:
        raise ToolExecutionError(f"Unknown capability: {cap.value}")

    # Generic validation: check required fields
    for field in contract.get("required", []):
        if not _first_string(raw.get(field)):
            raise ToolExecutionError(f"{cap.value} missing required metadata.{field}")

    # Capability-specific normalization
    if cap == ToolCapability.SHELL_EXEC:
        return _normalize_shell(raw)
    if cap == ToolCapability.SCRIPT_EXEC:
        return _normalize_script(raw, state)
    # All CLI tools: pass through validated metadata as-is
    return _normalize_cli_tool(raw, contract)


def _normalize_shell(raw: dict[str, object]) -> dict[str, object]:
    clean: dict[str, object] = {"command": _first_string(raw["command"])}
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    return clean


def _normalize_script(raw: dict[str, object], state: RunState) -> dict[str, object]:
    clean: dict[str, object] = {
        "script_code": _first_string(raw["script_code"]),
        "script_language": _normalize_script_language(
            _first_string(raw.get("script_language")) or "python"
        ),
        "files_root": _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT,
    }
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    challenge = state.metadata.get("challenge", {}) or {}
    if "flag_format" in challenge:
        clean["flag_format"] = challenge.get("flag_format") or ""
    return clean


def _normalize_cli_tool(raw: dict[str, object], contract: dict) -> dict[str, object]:
    """Pass through all required + optional fields that have values."""
    allowed = set(contract.get("required", [])) | set(contract.get("optional", []))
    clean: dict[str, object] = {}
    for key in allowed:
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean



def _normalize_script_language(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"python3", "py"}:
        return "python"
    if lowered in {"shell", "zsh"}:
        return "bash"
    return lowered or "python"
