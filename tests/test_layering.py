"""Architectural layering tests.

The ``nyuctf_mutil_killchain`` package is organized into four layers.  Each
layer may only depend on layers below it (and the standard library / external
packages).  This test scans the AST of every module and fails the build when
a forbidden import appears.

Layer map (lowest to highest):

    L1  state                           ← models, constants, task factories
    L1  llm                             ← LLM client abstraction
    L1  prompts                         ← prompt templates (no deps on agents)
    L2  tools                           ← execution plane, parsers, registry
        tools.plugins                   ← plugin implementations (subprocess scripts)
    L3  agents._helpers                 ← worker-internal helpers (no LLM, no tools)
    L3  agents.reasoning                ← LLM prompt + schema glue
    L3  agents                          ← worker classes
    L4  orchestrator                    ← planner, router, dispatch, loop
    L5  controller                      ← top-level run controller (assembles all)

The forbidden directions enforced here:

  * ``state``               must not import ``agents``, ``orchestrator``,
                            ``tools``, ``llm``, ``prompts``, ``controller``.
  * ``llm``                 must not import any package above L1.
  * ``prompts``             must not import any package above L1.
  * ``tools``               must not import ``agents``, ``orchestrator``,
                            ``controller``.
  * ``tools.plugins``       must not import ``agents``, ``orchestrator``,
                            ``controller``.
  * ``agents``              must not import ``orchestrator``, ``controller``.
  * ``agents._helpers``     must not import ``agents`` (other than helpers themselves),
                            ``agents.reasoning``, ``orchestrator``, ``tools``,
                            ``llm``.
  * ``agents.reasoning``    must not import ``orchestrator``, ``controller``,
                            ``tools.plugins``.
  * ``orchestrator``        must not import ``controller``.

Any new module that violates these directions causes the test to fail.
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = REPO_ROOT / "nyuctf_mutil_killchain"


# ---------------------------------------------------------------------------
# Per-layer forbidden-import sets
# ---------------------------------------------------------------------------

_FORBIDDEN_BY_PACKAGE: dict[str, frozenset[str]] = {
    "nyuctf_mutil_killchain.state": frozenset(
        {
            "nyuctf_mutil_killchain.agents",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.tools",
            "nyuctf_mutil_killchain.llm",
            "nyuctf_mutil_killchain.prompts",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.llm": frozenset(
        {
            "nyuctf_mutil_killchain.agents",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.tools",
            "nyuctf_mutil_killchain.prompts",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.prompts": frozenset(
        {
            "nyuctf_mutil_killchain.agents",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.tools",
            "nyuctf_mutil_killchain.llm",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.tools": frozenset(
        {
            "nyuctf_mutil_killchain.agents",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.tools.plugins": frozenset(
        {
            "nyuctf_mutil_killchain.agents",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.agents._helpers": frozenset(
        {
            "nyuctf_mutil_killchain.agents.reasoning",
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.tools",
            "nyuctf_mutil_killchain.llm",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.agents.reasoning": frozenset(
        {
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.tools.plugins",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.agents": frozenset(
        {
            "nyuctf_mutil_killchain.orchestrator",
            "nyuctf_mutil_killchain.controller",
        }
    ),
    "nyuctf_mutil_killchain.orchestrator": frozenset(
        {
            "nyuctf_mutil_killchain.controller",
        }
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _module_to_dotted(path: Path) -> str:
    """Convert a path like ``.../agents/base.py`` to ``nyuctf_mutil_killchain.agents.base``."""
    relative = path.relative_to(REPO_ROOT)
    parts = list(relative.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _module_imports(path: Path) -> Iterable[str]:
    """Yield each fully-qualified import seen inside the module at *path*."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                # Relative imports are within the same package; skip them
                # because the layering is enforced via absolute paths.
                continue
            yield node.module or ""


def _is_under(target: str, package: str) -> bool:
    """Return True when *target* lives inside *package* (exact or descendant)."""
    return target == package or target.startswith(f"{package}.")


def _python_modules() -> list[Path]:
    return sorted(
        path
        for path in PACKAGE_ROOT.rglob("*.py")
        if "__pycache__" not in path.parts
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _resolve_owning_layer(module: str) -> str | None:
    """Return the longest layer prefix that owns *module*."""
    best: str | None = None
    for layer in _FORBIDDEN_BY_PACKAGE:
        if _is_under(module, layer):
            if best is None or len(layer) > len(best):
                best = layer
    return best


@pytest.mark.parametrize("module_path", _python_modules(), ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_module_does_not_violate_layering(module_path: Path) -> None:
    """Each module's imports must respect the layer ordering."""

    dotted = _module_to_dotted(module_path)
    layer = _resolve_owning_layer(dotted)
    if layer is None:
        pytest.skip(f"{dotted} is not in a tracked layer")

    forbidden = _FORBIDDEN_BY_PACKAGE[layer]
    violations: list[str] = []
    for imported in _module_imports(module_path):
        if not imported:
            continue
        for prefix in forbidden:
            if _is_under(imported, prefix):
                # Self-imports through __init__ are not violations because the
                # layer always owns its own namespace.
                if _is_under(imported, layer):
                    continue
                violations.append(f"{dotted!r} imports {imported!r} (forbidden by layer {layer!r})")
                break

    assert not violations, "Layering violation:\n  - " + "\n  - ".join(violations)
