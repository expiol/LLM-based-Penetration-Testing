"""NYU CTF docker environment helpers."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from uuid import uuid4

from killchain_docker.logging_utils import get_logger
from killchain_docker.processes import run_bounded_process
from nyuctf.challenge import CTFChallenge

LOGGER = get_logger(__name__)
_DOCKER_COMMAND_TIMEOUT_S = 120
_DOCKER_CAPTURE_BYTES = 20_000
_MANAGED_LABEL = "killchain_docker.managed"
_CHALLENGE_LABEL = "killchain_docker.challenge"
_OWNER_PID_LABEL = "killchain_docker.owner_pid"
_LABEL_SAFE_RE = re.compile(r"[^A-Za-z0-9_.-]+")
_NO_SUCH_CONTAINER_RE = re.compile(r"No such container", re.IGNORECASE)


def _run_docker_command(cmd: list[str]) -> str:
    result = run_bounded_process(
        cmd,
        timeout_s=_DOCKER_COMMAND_TIMEOUT_S,
        max_output_bytes=_DOCKER_CAPTURE_BYTES,
    )
    if result.exit_code != 0:
        raise subprocess.CalledProcessError(
            result.exit_code,
            cmd,
            output=result.stdout,
            stderr=result.stderr,
        )
    return result.stdout.strip()


def _label_value(value: object, *, limit: int = 160) -> str:
    text = _LABEL_SAFE_RE.sub("_", str(value or "").strip()).strip("_")
    return (text or "unknown")[:limit]


def _owner_pid_alive(raw_pid: str) -> bool:
    try:
        pid = int(str(raw_pid).strip())
    except ValueError:
        return True
    if pid <= 0:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def cleanup_stale_managed_containers() -> None:
    """Remove execution containers whose owning process is gone."""

    try:
        rows = _run_docker_command(
            [
                "docker",
                "ps",
                "-a",
                "--filter",
                f"label={_MANAGED_LABEL}=true",
                "--format",
                f'{{{{.ID}}}}\t{{{{.Label "{_OWNER_PID_LABEL}"}}}}',
            ]
        )
    except (OSError, subprocess.CalledProcessError):
        LOGGER.debug(
            "failed to list stale managed containers",
            exc_info=True,
            extra={"label": _MANAGED_LABEL},
        )
        return

    for row in rows.splitlines():
        parts = row.split("\t", 1)
        if len(parts) != 2:
            continue
        container_id, owner_pid = parts
        if _owner_pid_alive(owner_pid):
            continue
        try:
            _run_docker_command(["docker", "rm", "-f", container_id])
        except (OSError, subprocess.CalledProcessError):
            LOGGER.debug(
                "failed to remove stale managed container",
                exc_info=True,
                extra={"container_id": container_id, "owner_pid": owner_pid},
            )
            continue


class CTFEnvironment:
    """Manages the persistent NYU agent container for one run."""

    def __init__(self, challenge: CTFChallenge, container_image: str, network: str):
        self.challenge = challenge
        self.container_image = container_image
        self.network = network
        self.container: str | None = None
        self.container_name: str | None = None

    def setup(self) -> None:
        self.start_docker()
        for file in self.challenge.files:
            hostpath = self.challenge.challenge_dir / file
            self.copy_into_container(hostpath, f"ctf_files/{file}")

    def teardown(self) -> None:
        self.stop_docker()

    def start_docker(self) -> None:
        cleanup_stale_managed_containers()
        self.container_name = (
            f"killchain-exec-{os.getpid()}-"
            f"{_label_value(self.challenge.canonical_name, limit=48)}-"
            f"{uuid4().hex[:8]}"
        )
        cmd = [
            "docker",
            "run",
            "-d",
            "--name",
            self.container_name,
            "--restart",
            "on-failure:3",
            "--label",
            f"{_MANAGED_LABEL}=true",
            "--label",
            f"{_CHALLENGE_LABEL}={_label_value(self.challenge.canonical_name)}",
            "--label",
            f"{_OWNER_PID_LABEL}={os.getpid()}",
            "--network",
            self.network,
            "--platform",
            "linux/amd64",
            self.container_image,
        ]
        self.container = _run_docker_command(cmd)

    def copy_into_container(self, hostpath: str | Path, filename: str | Path) -> Path:
        if self.container is None:
            raise RuntimeError("container is not running")

        hostpath = Path(hostpath)
        if Path(filename).is_absolute():
            containerpath = Path(filename)
        else:
            containerpath = self.container_home / filename
            _run_docker_command(
                [
                    "docker",
                    "exec",
                    self.container,
                    "mkdir",
                    "-p",
                    str(containerpath.parent),
                ]
            )

        _run_docker_command(
            [
                "docker",
                "cp",
                "-aq",
                str(hostpath),
                f"{self.container}:{containerpath}",
            ]
        )
        return containerpath

    def stop_docker(self) -> None:
        if not self.container:
            return
        try:
            _run_docker_command(["docker", "rm", "-f", self.container])
        except subprocess.CalledProcessError as exc:
            combined = "\n".join(
                part for part in (str(exc.stderr or ""), str(exc.output or "")) if part
            )
            if not _NO_SUCH_CONTAINER_RE.search(combined):
                raise
        finally:
            self.container = None
            self.container_name = None

    @property
    def container_home(self) -> Path:
        return Path("/home/ctfplayer")
