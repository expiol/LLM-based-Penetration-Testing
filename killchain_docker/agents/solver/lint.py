"""Static lint pre-check for LLM-generated solver code.

Run cheaply in-process before we ship the solver into the container's
``solver_execution`` plugin. We only catch deterministic, generic bugs:

1. ``empty`` — the LLM returned no body at all.
2. ``syntax`` — :func:`ast.parse` rejects the code.
3. ``missing_import`` — references a stdlib module name (``sys.exit``,
   ``os.chdir``, ``subprocess.run`` …) without the matching ``import``.

We intentionally do NOT lint for higher-level "did the script use the
right algorithm" patterns. Those are challenge-specific, expensive to
re-prompt, and the container itself will surface the real failure mode.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass


_LIKELY_STDLIB_MODULES = frozenset({
    "sys", "os", "re", "subprocess", "json", "binascii", "struct",
    "base64", "hashlib", "hmac", "tempfile", "pathlib", "socket",
    "itertools", "functools", "collections", "math", "random", "time",
    "string", "io", "shutil", "glob", "zlib", "gzip", "shlex",
})

_BUILTINS = frozenset(dir(builtins))


@dataclass(frozen=True)
class SolverLintResult:
    """Result of :func:`lint_solver_code`."""

    ok: bool
    error_kind: str = ""
    error_message: str = ""
    offending_lineno: int | None = None
    offending_line: str = ""

    @classmethod
    def success(cls) -> "SolverLintResult":
        return cls(ok=True)

    def fingerprint(self) -> str:
        if self.ok:
            return ""
        bits = [f"{self.error_kind}: {self.error_message}"]
        if self.offending_lineno is not None:
            bits.append(f"line {self.offending_lineno}")
        return " ".join(bits)


def lint_solver_code(code: str, language: str) -> SolverLintResult:
    """Return a :class:`SolverLintResult` describing the first failure, or success."""

    if not code or not code.strip():
        return SolverLintResult(
            ok=False,
            error_kind="empty",
            error_message="solver_code is empty or whitespace-only",
        )

    if language not in ("python", ""):
        return SolverLintResult.success()

    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        line_text = ""
        if exc.lineno is not None:
            try:
                line_text = code.splitlines()[exc.lineno - 1].rstrip()
            except IndexError:
                line_text = ""
        return SolverLintResult(
            ok=False,
            error_kind="syntax",
            error_message=str(exc.msg or exc),
            offending_lineno=exc.lineno,
            offending_line=line_text,
        )

    missing = _find_missing_stdlib_imports(tree)
    if missing:
        first_name, first_lineno = sorted(missing.items(), key=lambda kv: (kv[0], kv[1]))[0]
        line_text = ""
        try:
            line_text = code.splitlines()[first_lineno - 1].rstrip()
        except IndexError:
            line_text = ""
        names_str = ", ".join(sorted(missing))
        return SolverLintResult(
            ok=False,
            error_kind="missing_import",
            error_message=(
                f"name {first_name!r} used before being imported. "
                f"Add ``import {names_str}`` at the top of the script."
            ),
            offending_lineno=first_lineno,
            offending_line=line_text,
        )

    return SolverLintResult.success()


def _find_missing_stdlib_imports(tree: ast.Module) -> dict[str, int]:
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported.add(alias.asname or alias.name)
            if node.module:
                imported.add(node.module.split(".")[0])

    referenced: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            name = node.value.id
            if name in _LIKELY_STDLIB_MODULES and name not in imported and name not in _BUILTINS:
                existing = referenced.get(name)
                if existing is None or node.lineno < existing:
                    referenced[name] = node.lineno
    return referenced
