"""Static lint pre-check for LLM-generated solver code.

Run cheaply in-process before we ship the solver into the container's
``solver_execution`` plugin.  Catches the two failure modes that DeepSeek-V4
keeps producing in batch runs:

1. ``SyntaxError`` — unbalanced brackets, stray indentation, unterminated
   string literals.  Detected via :func:`ast.parse` and surfaced with the
   offending line so the LLM can fix the *specific* bug instead of starting
   over.
2. ``NameError: name 'X' is not defined`` for common stdlib modules — the
   LLM writes ``sys.exit(0)`` / ``os.chdir(...)`` / ``subprocess.run(...)``
   but forgets the matching ``import``.  Detected by walking the AST and
   comparing referenced names against imported names + builtins.

Non-Python solvers (bash, javascript, ...) skip the AST pass entirely and
only get the empty-code check.  Lints other than these two failure modes
are intentionally NOT included — false positives would cost more LLM calls
than the bug they catch.
"""

from __future__ import annotations

import ast
import builtins
from dataclasses import dataclass


# Stdlib module names that the solver prompt encourages and that previously
# generated NameError fingerprints when the LLM forgot ``import``.  Kept as a
# small allowlist on purpose: linting every possible undefined name would
# flood the loop with false positives whenever the LLM legitimately uses a
# bundled custom function it defines later in the script.
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
    #: One of ``"empty"``, ``"syntax"``, ``"missing_import"``, or ``""`` when ok.
    error_kind: str = ""
    #: Human-readable description, suitable for embedding in the next prompt.
    error_message: str = ""
    #: 1-indexed line where the offending code lives, when known.
    offending_lineno: int | None = None
    #: The raw line text (right-trimmed), when known.
    offending_line: str = ""

    @classmethod
    def success(cls) -> "SolverLintResult":
        return cls(ok=True)

    def fingerprint(self) -> str:
        """Return a short description suitable for retry prompts."""
        if self.ok:
            return ""
        bits = [f"{self.error_kind}: {self.error_message}"]
        if self.offending_lineno is not None:
            bits.append(f"line {self.offending_lineno}")
        return " ".join(bits)


def lint_solver_code(code: str, language: str) -> SolverLintResult:
    """Statically lint LLM-generated *code*.

    Returns a :class:`SolverLintResult` describing the first failure found,
    or :meth:`SolverLintResult.success` when the code passes.  Never raises.
    """
    if not code or not code.strip():
        return SolverLintResult(
            ok=False,
            error_kind="empty",
            error_message="solver_code is empty or whitespace-only",
        )

    if language not in ("python", ""):
        # Non-Python languages: only do the empty check; we have no cheap
        # in-process syntax validator for bash/js/etc.  The container will
        # surface their interpreter errors normally.
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
        # Pick the first one alphabetically for a deterministic fingerprint.
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
    """Return ``{module_name: first_use_lineno}`` for stdlib modules referenced but never imported.

    Only flags references to *modules* in :data:`_LIKELY_STDLIB_MODULES` —
    e.g. ``sys.exit`` or ``os.chdir``.  Bare ``Name`` references are ignored
    because they're usually local variables that get assigned later.
    """
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            # ``from x import y`` makes ``y`` a name, not ``x``; track the
            # imported leaf names so attribute accesses on submodules work.
            for alias in node.names:
                imported.add(alias.asname or alias.name)
            if node.module:
                imported.add(node.module.split(".")[0])

    referenced: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            name = node.value.id
            if name in _LIKELY_STDLIB_MODULES and name not in imported and name not in _BUILTINS:
                # Track the *earliest* source-line reference, since ``ast.walk``
                # visits nodes in BFS order which may report a deeply-nested
                # ``sys.stderr`` (line 2) AFTER a shallower ``sys.exit`` (line 3).
                existing = referenced.get(name)
                if existing is None or node.lineno < existing:
                    referenced[name] = node.lineno
    return referenced
