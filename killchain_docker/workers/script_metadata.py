"""script.exec metadata normalization and Python scratch-path rewriting."""

from __future__ import annotations
import ast
from killchain_docker.scope_guard import (
    ambient_filesystem_block_reason,
    python_ambient_filesystem_block_reason,
    scratch_path_reference_block_reason,
)
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.constants import DEFAULT_FILES_ROOT
from killchain_docker.state.run_state import RunState
from killchain_docker.tools.core import ToolExecutionError, _first_string


def normalize_script_metadata(
    raw: dict[str, object], state: RunState
) -> dict[str, object]:
    script_code = _first_string(raw["script_code"])
    script_language = normalize_script_language(
        _first_string(raw.get("script_language")) or "python"
    )
    if script_language == "python":
        validate_python_script(script_code)
    files_root = _first_string(raw.get("files_root")) or DEFAULT_FILES_ROOT
    if script_language == "python":
        ambient_reason = python_ambient_filesystem_block_reason(
            script_code, files_root=files_root, authorized_scope=state.authorized_scope
        )
    else:
        ambient_reason = ambient_filesystem_block_reason(
            script_code, files_root=files_root, authorized_scope=state.authorized_scope
        )
    if ambient_reason:
        raise ToolExecutionError(
            f"script.exec blocked: {ambient_reason}; use CTF_FILES_ROOT, CTF_TEMP_DIR, or relative paths"
        )
    if script_language == "python":
        script_code = rewrite_python_scratch_literals(script_code)
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
    flag_format = ChallengeProjection(state).flag_format()
    if flag_format:
        clean["flag_format"] = flag_format
    return clean


def validate_python_script(script_code: str) -> None:
    try:
        ast.parse(script_code)
    except SyntaxError as exc:
        line = f" line {exc.lineno}" if exc.lineno else ""
        raise ToolExecutionError(
            f"script.exec Python syntax invalid{line}: {exc.msg}"
        ) from exc


def rewrite_python_scratch_literals(script_code: str) -> str:
    """Rewrite direct Python string literal scratch paths to CTF_TEMP_DIR."""
    tree = ast.parse(script_code)
    rewriter = PythonScratchLiteralRewriter()
    rewritten = rewriter.visit(tree)
    if not rewriter.changed:
        return script_code
    assert isinstance(rewritten, ast.Module)
    ensure_os_import(rewritten)
    ast.fix_missing_locations(rewritten)
    return ast.unparse(rewritten)


class PythonScratchLiteralRewriter(ast.NodeTransformer):
    def __init__(self) -> None:
        self.changed = False

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.AST:
        return node

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if not isinstance(node.value, str):
            return node
        relative = scratch_literal_relative(node.value)
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
                    value=ast.Name(id="os", ctx=ast.Load()), attr="path", ctx=ast.Load()
                ),
                attr="join",
                ctx=ast.Load(),
            ),
            args=[temp_dir, ast.Constant(relative)],
            keywords=[],
        )
        return ast.copy_location(replacement, node)


def scratch_literal_relative(value: str) -> str | None:
    normalized = value.replace("\\", "/")
    for prefix in ("/private/tmp", "/var/tmp", "/tmp"):
        if normalized == prefix:
            return ""
        if normalized.startswith(f"{prefix}/"):
            return normalized[len(prefix) :].lstrip("/")
    return None


def ensure_os_import(tree: ast.Module) -> None:
    for node in tree.body:
        if isinstance(node, ast.Import) and any(
            (alias.name == "os" for alias in node.names)
        ):
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
        if not (isinstance(node, ast.ImportFrom) and node.module == "__future__"):
            break
        insert_at += 1
    tree.body.insert(insert_at, ast.Import(names=[ast.alias(name="os")]))


def normalize_script_language(value: str) -> str:
    lowered = value.strip().lower()
    if lowered in {"python3", "py"}:
        return "python"
    if lowered in {"shell", "zsh"}:
        return "bash"
    return lowered or "python"
