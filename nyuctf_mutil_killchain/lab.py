"""Docker Compose lab lifecycle — optional helpers for local benchmark targets.

These functions are **not** invoked by ``run_assessment`` automatically; call them from
scripts, CI, or after wiring a ``lab`` CLI subcommand. Safe defaults: compose file path
is explicit, no shell interpolation.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from urllib import error, request

DEFAULT_COMPOSE_REL = Path("docker/docker-compose.lab.yml")


def _compose_argv(compose_file: Path) -> list[str]:
    return ["docker", "compose", "-f", str(compose_file.resolve())]


def lab_up(compose_file: str | Path | None = None, *, detach: bool = True) -> int:
    """Run ``docker compose up`` (with ``-d`` when ``detach`` is True). Returns exit code."""

    path = Path(compose_file or DEFAULT_COMPOSE_REL)
    if not path.is_file():
        raise FileNotFoundError(
            f"Compose file not found: {path}. "
            f"Copy docker/docker-compose.lab.yml.example to {DEFAULT_COMPOSE_REL} and edit."
        )
    if shutil.which("docker") is None:
        raise RuntimeError("docker executable not found on PATH")

    cmd = [*_compose_argv(path), "up"]
    if detach:
        cmd.append("-d")
    return subprocess.run(cmd, check=False).returncode


def lab_down(compose_file: str | Path | None = None, *, remove_volumes: bool = False) -> int:
    """Run ``docker compose down``. Returns exit code."""

    path = Path(compose_file or DEFAULT_COMPOSE_REL)
    if not path.is_file():
        raise FileNotFoundError(
            f"Compose file not found: {path}. "
            f"Copy docker/docker-compose.lab.yml.example to {DEFAULT_COMPOSE_REL} and edit."
        )
    if shutil.which("docker") is None:
        raise RuntimeError("docker executable not found on PATH")

    cmd = [*_compose_argv(path), "down"]
    if remove_volumes:
        cmd.append("-v")
    return subprocess.run(cmd, check=False).returncode


def lab_health_check(url: str, *, timeout_s: float = 15.0) -> bool:
    """Return True if an HTTP GET to ``url`` reaches a listening server (2xx–4xx count as up)."""

    req = request.Request(url, method="GET", headers={"User-Agent": "autopentest-lab-health/1"})
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
            return 200 <= getattr(resp, "status", 200) < 600
    except error.HTTPError as exc:
        return exc.code < 500
    except error.URLError:
        return False
