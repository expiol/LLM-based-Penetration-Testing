"""Execution-plane factory — registers all plugins."""

from __future__ import annotations

from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.tools.plugins import ALL_PLUGINS


def build_execution_plane(
    *,
    argv_prefix: list[str] | None = None,
    python_executable: str | None = None,
) -> ExecutionPlane:
    """Create the default execution plane with all plugins registered.

    Parameters
    ----------
    argv_prefix:
        Command prefix prepended to every subprocess invocation (e.g.
        ``["docker", "exec", "<container>"]``).
    python_executable:
        Override the Python interpreter used by :class:`ScriptPlugin`
        (default ``"python3"``).  Useful when the target container ships
        a non-standard interpreter name.
    """
    plane = ExecutionPlane()
    prefix = list(argv_prefix or [])
    for plugin_cls, output_builder in ALL_PLUGINS:
        kwargs: dict[str, object] = {"argv_prefix": prefix}
        if python_executable and hasattr(plugin_cls, "python_executable"):
            kwargs["python_executable"] = python_executable
        plane.register(plugin_cls(**kwargs), output_builder)
    return plane
