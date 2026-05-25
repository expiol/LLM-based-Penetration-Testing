"""Shared execution-scope guardrails.

The planner and tools both need a small deterministic boundary layer: CTF
workers may inspect challenge files and authorized services, but they should
not pivot into the runner's ambient host/container environment when a remote
endpoint fails.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import urlparse

from killchain_docker.state.constants import DEFAULT_FILES_ROOT


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
_LOOPBACK_RE = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[?::1\]?)(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)
_NETWORK_CLIENT_RE = re.compile(
    r"\b(?:curl|wget|nc|netcat|telnet|nmap|socat|openssl\s+s_client)\b",
    re.IGNORECASE,
)
_BROAD_ENV_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?:home(?:/[^/\s;&|]*)?|root|etc|var|opt|srv|usr(?:/local)?)(?:\b|/)",
    re.IGNORECASE,
)
_BROAD_FLAG_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?:tmp|home(?:/[^/\s;&|]*)?|root|etc|var|opt|srv|usr(?:/local)?)(?:\b|/)",
    re.IGNORECASE,
)
_ROOT_SENSITIVE_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?:flag|secret|token|credential|password)(?:\b|/)",
    re.IGNORECASE,
)
_BROAD_FILE_TOOL_RE = re.compile(
    r"(?<![.\w])(?:find|grep|rg|ag|ack|ls|cat|sed|awk|head|tail)(?![\w])",
    re.IGNORECASE,
)
_FLAG_HUNT_RE = re.compile(r"\b(?:flag|secret|token|credential|password)\b", re.IGNORECASE)
_ENV_DOTFILE_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?:home/[^/\s;&|]+|root)/"
    r"(?:\.bashrc|\.profile|\.bash_profile|\.bash_history|\.zshrc|"
    r"\.entrypoint\.sh|\.ssh(?:/|\b)|\.env(?:\b|/))",
    re.IGNORECASE,
)
_SCRATCH_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_./-])/(?:tmp|var/tmp|private/tmp)(?:\b|/)",
    re.IGNORECASE,
)
_PREVIOUS_GENERATED_ARTIFACT_RE = re.compile(
    r"\b(?:open|read|parse|inspect|analy[sz]e|render|use|load)\b"
    r".{0,80}\b(?:already[- ]saved|saved|generated|created|written|decrypted|output)\b"
    r"|\bevidence-[0-9a-fA-F]+\b",
    re.IGNORECASE | re.DOTALL,
)


def normalize_authorized_scope(raw: object) -> tuple[str, ...]:
    """Normalize an authorized_scope-like value to non-empty strings."""

    if raw is None:
        return ()
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        items = [str(item) for item in raw if item not in (None, "")]
    else:
        items = [str(raw)]
    return tuple(item.strip() for item in items if item and item.strip())


def _scope_hostname(scope: str) -> str:
    text = str(scope or "").strip()
    if not text:
        return ""
    candidate = text if "://" in text else f"//{text}"
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ""
    return (parsed.hostname or "").strip("[]").lower()


def scope_allows_loopback(authorized_scope: object) -> bool:
    """Return true when loopback is explicitly part of authorized scope."""

    for scope in normalize_authorized_scope(authorized_scope):
        hostname = _scope_hostname(scope)
        if hostname in _LOOPBACK_HOSTS or hostname.startswith("127."):
            return True
    return False


def text_mentions_loopback(text: object) -> bool:
    return bool(_LOOPBACK_RE.search(str(text or "")))


def loopback_reference_block_reason(
    text: object,
    authorized_scope: object,
    *,
    require_network_client: bool = False,
) -> str | None:
    """Block localhost/127.0.0.1 targets unless explicitly authorized."""

    scopes = normalize_authorized_scope(authorized_scope)
    if not scopes or scope_allows_loopback(scopes):
        return None
    body = str(text or "")
    if not text_mentions_loopback(body):
        return None
    if require_network_client and not _NETWORK_CLIENT_RE.search(body):
        return None
    return "loopback target is outside authorized_scope"


def _remove_allowed_files_root(text: str, files_root: object) -> str:
    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    if not root:
        return text
    variants = {
        root,
        root.replace("'", "'\\''"),
        root.replace(" ", r"\ "),
    }
    cleaned = text
    for variant in sorted(variants, key=len, reverse=True):
        cleaned = cleaned.replace(variant, "__CTF_FILES_ROOT__")
    return cleaned


def ambient_filesystem_block_reason(
    text: object,
    *,
    files_root: object = DEFAULT_FILES_ROOT,
    authorized_scope: object = None,
) -> str | None:
    """Block ambient environment exploration when an authorized scope exists."""

    if not normalize_authorized_scope(authorized_scope):
        return None
    body = _remove_allowed_files_root(str(text or ""), files_root)
    if _ENV_DOTFILE_RE.search(body):
        return "ambient home/root startup files are outside the challenge scope"
    if not _BROAD_FILE_TOOL_RE.search(body):
        return None
    if _BROAD_ENV_PATH_RE.search(body):
        return "filesystem exploration must stay under files_root or explicit challenge files"
    if _ROOT_SENSITIVE_PATH_RE.search(body):
        return "ambient flag/secret search outside files_root is not permitted"
    if _FLAG_HUNT_RE.search(body) and _BROAD_FLAG_PATH_RE.search(body):
        return "ambient flag/secret search outside files_root is not permitted"
    return None


def python_ambient_filesystem_block_reason(
    code: object,
    *,
    files_root: object = DEFAULT_FILES_ROOT,
    authorized_scope: object = None,
) -> str | None:
    """Block ambient filesystem access in Python code without scanning strings as shell."""

    if not normalize_authorized_scope(authorized_scope):
        return None
    try:
        tree = ast.parse(str(code or ""))
    except SyntaxError:
        return ambient_filesystem_block_reason(
            code,
            files_root=files_root,
            authorized_scope=authorized_scope,
        )

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        shell_text = _python_shell_command_text(node)
        if shell_text:
            reason = ambient_filesystem_block_reason(
                shell_text,
                files_root=files_root,
                authorized_scope=authorized_scope,
            )
            if reason:
                return reason
        for path in _python_local_file_call_paths(node):
            reason = _ambient_path_reason(path, files_root=files_root)
            if reason:
                return reason
    return None


def _python_shell_command_text(node: ast.Call) -> str | None:
    name = _python_call_name(node.func)
    if name in {"os.system", "subprocess.getoutput", "subprocess.getstatusoutput"}:
        if node.args:
            return _literal_shell_command(node.args[0])
        return None
    if name in {
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.run",
        "subprocess.Popen",
    }:
        if node.args:
            return _literal_shell_command(node.args[0])
        return None
    return None


def _python_local_file_call_paths(node: ast.Call) -> list[str]:
    name = _python_call_name(node.func)
    if name in {"open", "builtins.open", "io.open", "pathlib.Path"} and node.args:
        return _literal_path_values(node.args[0])
    method = name.rsplit(".", 1)[-1]
    if method in {
        "read_text",
        "read_bytes",
        "write_text",
        "write_bytes",
        "open",
        "glob",
        "rglob",
        "iterdir",
        "exists",
        "is_file",
        "is_dir",
        "mkdir",
        "unlink",
    }:
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        return _literal_path_values(receiver)
    return []


def _python_call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _python_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _literal_shell_command(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        return node.value.decode("utf-8", "ignore") if isinstance(node.value, bytes) else node.value
    if isinstance(node, (ast.List, ast.Tuple)):
        parts: list[str] = []
        for element in node.elts:
            if not isinstance(element, ast.Constant) or not isinstance(element.value, (str, bytes)):
                return None
            value = element.value.decode("utf-8", "ignore") if isinstance(element.value, bytes) else element.value
            parts.append(value)
        return " ".join(parts)
    return None


def _literal_path_values(node: ast.AST | None) -> list[str]:
    if node is None:
        return []
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.Call) and _python_call_name(node.func) == "pathlib.Path" and node.args:
        return _literal_path_values(node.args[0])
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        values: list[str] = []
        values.extend(_literal_path_values(node.left))
        values.extend(_literal_path_values(node.right))
        return values
    return []


def _ambient_path_reason(path: str, *, files_root: object = DEFAULT_FILES_ROOT) -> str | None:
    body = _remove_allowed_files_root(str(path or ""), files_root)
    if _ENV_DOTFILE_RE.search(body):
        return "ambient home/root startup files are outside the challenge scope"
    if _BROAD_ENV_PATH_RE.search(body):
        return "filesystem exploration must stay under files_root or explicit challenge files"
    if _FLAG_HUNT_RE.search(body) and _BROAD_FLAG_PATH_RE.search(body):
        return "ambient flag/secret search outside files_root is not permitted"
    if _ROOT_SENSITIVE_PATH_RE.search(body):
        return "ambient flag/secret search outside files_root is not permitted"
    return None


def todo_loopback_block_reason(
    *,
    goal: object,
    context: dict[str, object],
    authorized_scope: object,
) -> str | None:
    """Return a scope violation reason for planner todo references."""

    fields = [
        str(goal or ""),
        *(str(context.get(key) or "") for key in ("scope", "url", "base_url", "host", "hostname", "server_name")),
    ]
    return loopback_reference_block_reason("\n".join(fields), authorized_scope)


def todo_scratch_dependency_reason(*, goal: object, context: dict[str, object]) -> str | None:
    """Block planner todos that depend on prior scratch-directory files."""

    fields = [str(goal or ""), *(str(value) for value in (context or {}).values())]
    if _SCRATCH_PATH_RE.search("\n".join(fields)):
        return "planner todo depends on scratch path from a previous step"
    return None


def _remove_allowed_paths(text: str, allowed_paths: object = None) -> str:
    if not isinstance(allowed_paths, (list, tuple, set, frozenset)):
        return text
    cleaned = text
    for raw in sorted((str(path or "") for path in allowed_paths), key=len, reverse=True):
        path = raw.strip()
        if not path:
            continue
        cleaned = cleaned.replace(path, "__REGISTERED_ARTIFACT__")
    return cleaned


def todo_registered_scratch_dependency_reason(
    *,
    goal: object,
    context: dict[str, object],
    allowed_artifact_paths: object = None,
) -> str | None:
    """Block scratch references except paths already registered as artifacts."""

    fields = [str(goal or ""), *(str(value) for value in (context or {}).values())]
    text = _remove_allowed_paths("\n".join(fields), allowed_artifact_paths)
    if _SCRATCH_PATH_RE.search(text):
        return "planner todo depends on scratch path from a previous step"
    return None


def scratch_path_reference_block_reason(text: object) -> str | None:
    """Block direct scratch-directory references in generated tool code.

    Tool wrappers provide ``CTF_TEMP_DIR``/``TMPDIR`` for disposable scratch
    files. Direct ``/tmp`` references can leak large artifacts across tool
    calls and fill the container overlay.
    """

    if _SCRATCH_PATH_RE.search(str(text or "")):
        return "scratch files must use CTF_TEMP_DIR or relative paths, not /tmp"
    return None


def todo_ephemeral_artifact_dependency_reason(
    *,
    goal: object,
    context: dict[str, object],
    challenge_files: object = None,
    files_root: object = DEFAULT_FILES_ROOT,
    allowed_artifact_paths: object = None,
) -> str | None:
    """Block planner todos that depend on non-durable files from prior tools.

    shell.exec and script.exec run with workspace snapshot protection, so files
    generated in one tool call should be treated as stdout evidence, not as
    durable filesystem state for later todos.
    """

    text = _remove_allowed_paths(
        "\n".join([str(goal or ""), *(str(value) for value in (context or {}).values())]),
        allowed_artifact_paths,
    )
    if not _PREVIOUS_GENERATED_ARTIFACT_RE.search(text):
        return None

    root = str(files_root or DEFAULT_FILES_ROOT).rstrip("/")
    if not root:
        return None
    path_re = re.compile(
        re.escape(root) + r"/([A-Za-z0-9][A-Za-z0-9._@%+=,/-]{0,200})"
    )
    referenced = [match.group(1).strip("/ ") for match in path_re.finditer(text)]
    if not referenced:
        return None

    raw_files = challenge_files if isinstance(challenge_files, (list, tuple, set, frozenset)) else []
    original = {str(path).strip("/").split("/")[-1] for path in raw_files if str(path or "").strip()}
    for path in referenced:
        if path == ".autopentest_artifacts" or path.startswith(".autopentest_artifacts/"):
            continue
        basename = path.split("/")[-1]
        if basename and basename not in original:
            return "planner todo depends on non-durable generated artifact from a previous tool call"
    return None


__all__ = [
    "ambient_filesystem_block_reason",
    "loopback_reference_block_reason",
    "normalize_authorized_scope",
    "python_ambient_filesystem_block_reason",
    "scope_allows_loopback",
    "text_mentions_loopback",
    "todo_loopback_block_reason",
    "todo_scratch_dependency_reason",
    "todo_registered_scratch_dependency_reason",
    "todo_ephemeral_artifact_dependency_reason",
    "scratch_path_reference_block_reason",
]
