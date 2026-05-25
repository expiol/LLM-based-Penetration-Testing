"""Normalize worker-selected metadata before invoking tool plugins.

Each capability has a contract (required/optional fields + usage notes)
and a normalize function that validates & cleans metadata before dispatch.
"""

from __future__ import annotations

import ast

from killchain_docker.state import RunState, TodoItem
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.tools import ToolCapability, ToolExecutionError
from killchain_docker.tools.core import _first_string
from killchain_docker.tools.guard_policy import ToolGuardPolicy
from killchain_docker.tools.plugins.curl import unsupported_url_scheme_reason

# ---------------------------------------------------------------------------
# Metadata contracts — shown to the LLM during tool selection
# ---------------------------------------------------------------------------

_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.SHELL_EXEC: {
        "required": ["command"],
        "optional": ["files_root", "timeout_s", "max_workspace_mb"],
        "notes": (
            "Free-form bash -c. Use installed tools with pipes/redirects. "
            "Do not run package-manager updates/installs or language package installs; "
            "if a tool is missing, record that and pivot. Challenge-file changes are "
            "discarded after execution; scratch growth is capped by max_workspace_mb "
            "(default 512). Use CTF_TEMP_DIR for scratch files and write durable "
            "evidence to stdout. Do not use curl/wget for tcp:// or custom raw "
            "services; use script.exec with stdlib sockets instead. Keep stderr "
            "visible; do not hide tool failures with 2>/dev/null or &>/dev/null."
        ),
    },
    ToolCapability.SCRIPT_EXEC: {
        "required": ["script_code"],
        "optional": ["script_language", "files_root", "timeout_s", "max_workspace_mb"],
        "notes": (
            "Write self-contained bounded source. Default python. Supported: python, bash, "
            "sh, javascript, ruby, perl. Avoid package installation and unbounded loops; "
            "use fast-forward math or capped diagnostics for large counters/search spaces. "
            "Runs in a disposable copy of files_root; use CTF_FILES_ROOT or relative paths "
            "for challenge files and CTF_TEMP_DIR/tempfile for scratch files. Scratch "
            "growth is capped by max_workspace_mb (default 512)."
        ),
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
            "HTTP/HTTPS request only. method default 'GET'. headers is a dict. data is string body. "
            "session_id enables cookie jar persistence across requests (same id = same cookies). "
            "cookies is a string 'k1=v1; k2=v2' for one-shot cookies. "
            "follow_redirects=true adds -L. auth is 'user:pass' for HTTP basic auth. "
            "For tcp:// or custom binary/text protocols, use script.exec with sockets."
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
            "path", "file_path", "artifact_path", "challenge_files", "files_root",
            "output_dir", "max_files", "max_extract_mb", "offset", "offsets",
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
            "path", "file_path", "artifact_path", "challenge_files", "files_root",
            "output_dir", "max_entries", "max_artifacts", "max_extract_mb",
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
            "path", "paths", "file_path", "artifact_path", "challenge_files",
            "files_root", "max_files", "max_extract_mb",
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
            "path", "file_path", "artifact_path", "challenge_files", "files_root",
            "output_dir", "max_extract_mb", "max_lsb_bytes",
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
    ToolCapability.BINWALK: {
        "required": ["path"],
        "optional": ["extract", "files_root", "max_extract_mb"],
        "notes": (
            "Firmware/binary analysis. Set extract=true to carve embedded files in a "
            "bounded disposable workspace; max_extract_mb caps extraction growth."
        ),
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
    ToolCapability.CHECKSEC: {
        "required": ["path"],
        "optional": [],
        "notes": "Binary security properties (NX, PIE, canary, RELRO). Returns protection status and attack surface hints.",
    },
    ToolCapability.LTRACE: {
        "required": ["path"],
        "optional": ["args", "filter", "input_data"],
        "notes": (
            "Trace library calls. Reveals strcmp/memcmp args (potential flags/passwords), "
            "crypto function parameters, buffer sizes. "
            "filter e.g. 'strcmp+memcmp+strncmp'. input_data sent via stdin."
        ),
    },
    ToolCapability.STRACE: {
        "required": ["path"],
        "optional": ["args", "filter", "input_data"],
        "notes": (
            "Trace system calls. Reveals file paths accessed (open/openat), "
            "network connections, and runtime behavior. "
            "filter e.g. 'trace=open,read,write' or 'trace=network'. input_data sent via stdin."
        ),
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
    contract = _CONTRACTS.get(cap)
    if not contract:
        raise ToolExecutionError(f"Unknown capability: {cap.value}")
    raw = _merge_tool_metadata(contract, todo.context, selected_metadata)

    # Generic validation: check required fields
    for field in contract.get("required", []):
        if not _first_string(raw.get(field)):
            raise ToolExecutionError(f"{cap.value} missing required metadata.{field}")

    # Capability-specific normalization
    if cap == ToolCapability.SHELL_EXEC:
        return _normalize_shell(raw, state)
    if cap == ToolCapability.SCRIPT_EXEC:
        return _normalize_script(raw, state)
    if cap == ToolCapability.CURL:
        return _normalize_curl(raw, contract)
    if cap == ToolCapability.ARTIFACT_TRIAGE:
        return _normalize_artifact_triage(raw)
    if cap == ToolCapability.DISK_EXTRACT:
        return _normalize_disk_extract(raw)
    if cap == ToolCapability.OFFICE_INSPECT:
        return _normalize_office_inspect(raw)
    if cap == ToolCapability.MEDIA_SCAN:
        return _normalize_media_scan(raw)
    if cap == ToolCapability.PNG_INSPECT:
        return _normalize_png_inspect(raw)
    # All CLI tools: pass through validated metadata as-is
    if "path" in contract.get("required", []):
        raw["files_root"] = (
            _first_string(raw.get("files_root"))
            or _first_string(todo.context.get("files_root"))
            or DEFAULT_FILES_ROOT
        )
    return _normalize_cli_tool(raw, contract)


def _merge_tool_metadata(
    contract: dict[str, object],
    todo_context: dict[str, object],
    selected_metadata: dict[str, object],
) -> dict[str, object]:
    """Merge tool metadata with the current LLM decision as the authority.

    Required tool fields are executable action fields, so they must come from
    this tool decision.  Todo context may provide optional defaults such as
    files_root, timeout_s, or session ids, but it cannot override what the
    worker selected for this dispatch.
    """
    required = set(contract.get("required", []))
    optional = set(contract.get("optional", []))
    raw: dict[str, object] = {
        key: value
        for key, value in todo_context.items()
        if key in optional and key not in required
    }
    raw.update(selected_metadata)
    return raw


def _normalize_shell(raw: dict[str, object], state: RunState) -> dict[str, object]:
    command = _first_string(raw["command"])
    _validate_shell_command(command)
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    scope_reason = scratch_path_reference_block_reason(command) or ambient_filesystem_block_reason(
        command,
        files_root=files_root,
        authorized_scope=state.authorized_scope,
    )
    if scope_reason:
        raise ToolExecutionError(
            f"shell.exec blocked: {scope_reason}; use files_root-bound paths or CTF_TEMP_DIR"
        )
    clean: dict[str, object] = {
        "command": command,
        "files_root": files_root,
        "authorized_scope": list(state.authorized_scope),
    }
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    if "max_workspace_mb" in raw:
        clean["max_workspace_mb"] = raw["max_workspace_mb"]
    return clean


def _validate_shell_command(command: str) -> None:
    reason = ToolGuardPolicy.shell_command_block_reason(command)
    if reason:
        raise ToolExecutionError(reason)


def _normalize_curl(raw: dict[str, object], contract: dict[str, object]) -> dict[str, object]:
    url = _first_string(raw["url"])
    scheme_reason = unsupported_url_scheme_reason(url)
    if scheme_reason:
        raise ToolExecutionError(f"curl blocked: {scheme_reason}")
    return _normalize_cli_tool(raw, contract)


def _normalize_artifact_triage(raw: dict[str, object]) -> dict[str, object]:
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    clean: dict[str, object] = {"files_root": files_root}
    paths = _artifact_triage_paths(raw)
    if paths:
        clean["paths"] = [_normalize_challenge_path(path, files_root) for path in paths]
    if "max_strings" in raw:
        clean["max_strings"] = raw["max_strings"]
    return clean


def _artifact_triage_paths(raw: dict[str, object]) -> list[object]:
    value = raw.get("paths")
    if isinstance(value, (list, tuple, set)):
        return [item for item in value if _first_string(item)]
    path = raw.get("path")
    if _first_string(path):
        return [path]
    for key in ("challenge_files",):
        value = raw.get(key)
        if isinstance(value, (list, tuple, set)):
            return [item for item in value if _first_string(item)]
    return []


def _normalize_disk_extract(raw: dict[str, object]) -> dict[str, object]:
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or _first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("disk.extract missing metadata.path")
    clean: dict[str, object] = {
        "path": _normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in (
        "output_dir", "max_files", "max_extract_mb", "offset",
        "offsets", "partition_offset",
    ):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def _normalize_office_inspect(raw: dict[str, object]) -> dict[str, object]:
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or _first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("office.inspect missing metadata.path")
    clean: dict[str, object] = {
        "path": _normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in (
        "output_dir", "max_entries", "max_artifacts", "max_extract_mb",
        "max_text_chars",
    ):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def _normalize_png_inspect(raw: dict[str, object]) -> dict[str, object]:
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    path = (
        _first_string(raw.get("path"))
        or _first_string(raw.get("artifact_path"))
        or _first_string(raw.get("file_path"))
        or _first_challenge_file(raw)
    )
    if not path:
        raise ToolExecutionError("png.inspect missing metadata.path")
    clean: dict[str, object] = {
        "path": _normalize_challenge_path(path, files_root),
        "files_root": files_root,
    }
    for key in ("output_dir", "max_extract_mb", "max_lsb_bytes"):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def _normalize_media_scan(raw: dict[str, object]) -> dict[str, object]:
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    paths = _media_scan_paths(raw)
    if not paths:
        raise ToolExecutionError("media.scan missing metadata.path or metadata.paths")
    clean: dict[str, object] = {
        "paths": [_normalize_challenge_path(path, files_root) for path in paths],
        "files_root": files_root,
    }
    if len(clean["paths"]) == 1:
        clean["path"] = clean["paths"][0]
    for key in ("max_files", "max_extract_mb"):
        if key in raw and raw[key] not in (None, "", [], {}):
            clean[key] = raw[key]
    return clean


def _media_scan_paths(raw: dict[str, object]) -> list[object]:
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


def _first_challenge_file(raw: dict[str, object]) -> str:
    value = raw.get("challenge_files")
    if isinstance(value, (list, tuple, set)):
        for item in value:
            text = _first_string(item)
            if text:
                return text
    return ""


def _normalize_script(raw: dict[str, object], state: RunState) -> dict[str, object]:
    script_code = _first_string(raw["script_code"])
    script_language = _normalize_script_language(
        _first_string(raw.get("script_language")) or "python"
    )
    if script_language == "python":
        _validate_python_script(script_code)
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    ambient_reason = ambient_filesystem_block_reason(
        script_code,
        files_root=files_root,
        authorized_scope=state.authorized_scope,
    )
    if ambient_reason:
        raise ToolExecutionError(
            f"script.exec blocked: {ambient_reason}; use CTF_FILES_ROOT, CTF_TEMP_DIR, or relative paths"
        )
    if script_language == "python":
        script_code = _rewrite_python_scratch_literals(script_code)
    scope_reason = scratch_path_reference_block_reason(script_code)
    if scope_reason:
        raise ToolExecutionError(
            f"script.exec blocked: {scope_reason}; use CTF_FILES_ROOT, CTF_TEMP_DIR, or relative paths"
        )
    clean: dict[str, object] = {
        "script_code": script_code,
        "script_language": script_language,
        "files_root": files_root,
        "authorized_scope": list(state.authorized_scope),
    }
    if "timeout_s" in raw:
        clean["timeout_s"] = raw["timeout_s"]
    if "max_workspace_mb" in raw:
        clean["max_workspace_mb"] = raw["max_workspace_mb"]
    challenge = state.metadata.get("challenge", {}) or {}
    if "flag_format" in challenge:
        clean["flag_format"] = challenge.get("flag_format") or ""
    return clean


def _validate_python_script(script_code: str) -> None:
    try:
        ast.parse(script_code)
    except SyntaxError as exc:
        line = f" line {exc.lineno}" if exc.lineno else ""
        raise ToolExecutionError(
            f"script.exec Python syntax invalid{line}: {exc.msg}"
        ) from exc


def _rewrite_python_scratch_literals(script_code: str) -> str:
    """Rewrite direct Python string literal scratch paths to CTF_TEMP_DIR.

    This keeps the overlay-protection invariant without spending additional
    LLM cycles on mechanical `/tmp/foo` to `CTF_TEMP_DIR/foo` repairs. Ambient
    filesystem exploration is checked before this rewrite, so broad flag hunts
    such as `grep -R flag /tmp` are still blocked rather than redirected.
    """

    tree = ast.parse(script_code)
    rewriter = _PythonScratchLiteralRewriter()
    rewritten = rewriter.visit(tree)
    if not rewriter.changed:
        return script_code
    assert isinstance(rewritten, ast.Module)
    _ensure_os_import(rewritten)
    ast.fix_missing_locations(rewritten)
    return ast.unparse(rewritten)


class _PythonScratchLiteralRewriter(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changed = False

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, str):
            return node
        relative = _scratch_literal_relative(node.value)
        if relative is None:
            return node
        self.changed = True
        temp_dir = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="os", ctx=ast.Load()),
                    attr="environ",
                    ctx=ast.Load(),
                ),
                attr="get",
                ctx=ast.Load(),
            ),
            args=[ast.Constant("CTF_TEMP_DIR"), ast.Constant(".")],
            keywords=[],
        )
        if not relative:
            return ast.copy_location(temp_dir, node)
        replacement = ast.Call(
            func=ast.Attribute(
                value=ast.Attribute(
                    value=ast.Name(id="os", ctx=ast.Load()),
                    attr="path",
                    ctx=ast.Load(),
                ),
                attr="join",
                ctx=ast.Load(),
            ),
            args=[temp_dir, ast.Constant(relative)],
            keywords=[],
        )
        return ast.copy_location(replacement, node)


def _scratch_literal_relative(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    for prefix in ("/private/tmp", "/var/tmp", "/tmp"):
        if normalized == prefix:
            return ""
        if normalized.startswith(f"{prefix}/"):
            return normalized[len(prefix):].lstrip("/")
    return None


def _ensure_os_import(tree: ast.Module) -> None:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(alias.name == "os" for alias in node.names):
            return
    insert_at = 0
    if (
        tree.body
        and isinstance(tree.body[0], ast.Expr)
        and isinstance(tree.body[0].value, ast.Constant)
        and isinstance(tree.body[0].value.value, str)
    ):
        insert_at = 1
    while insert_at < len(tree.body):
        node = tree.body[insert_at]
        if not (
            isinstance(node, ast.ImportFrom)
            and node.module == "__future__"
        ):
            break
        insert_at += 1
    tree.body.insert(insert_at, ast.Import(names=[ast.alias(name="os")]))


def _normalize_cli_tool(raw: dict[str, object], contract: dict) -> dict[str, object]:
    """Pass through all required + optional fields that have values."""
    allowed = set(contract.get("required", [])) | set(contract.get("optional", []))
    clean: dict[str, object] = {}
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    for key in allowed:
        if key in raw and raw[key] not in (None, "", [], {}):
            if key == "path":
                clean[key] = _normalize_challenge_path(raw[key], files_root)
            else:
                clean[key] = raw[key]
    return clean


def _normalize_challenge_path(value: object, files_root: str) -> str:
    path = (_first_string(value) or "").strip()
    if not path:
        return path
    if _path_shell_fragment(path):
        raise ToolExecutionError(
            "CLI tool path looks like a shell fragment; pass a single path or use shell.exec"
        )
    if path.startswith("/") or "://" in path:
        return path
    if path.startswith("./"):
        path = path[2:]
    return f"{files_root.rstrip('/')}/{path}"


def _path_shell_fragment(path: str) -> bool:
    return any(token in path for token in ("\n", "\r", ";", "&&", "||", "|", "`", "$(", ">", "<"))


def _normalize_script_language(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"python3", "py"}:
        return "python"
    if lowered in {"shell", "zsh"}:
        return "bash"
    return lowered or "python"
