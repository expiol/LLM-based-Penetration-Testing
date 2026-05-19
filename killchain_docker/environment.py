"""NYU CTF docker environment helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

from killchain_docker.processes import run_bounded_process
from nyuctf.challenge import CTFChallenge

_DOCKER_COMMAND_TIMEOUT_S = 120
_DOCKER_CAPTURE_BYTES = 20_000


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


class CTFEnvironment:
    """Manages the persistent NYU agent container for one run."""

    def __init__(self, challenge: CTFChallenge, container_image: str, network: str):
        self.challenge = challenge
        self.container_image = container_image
        self.network = network
        self.container: str | None = None

    def setup(self) -> None:
        self.start_docker()
        for file in self.challenge.files:
            hostpath = self.challenge.challenge_dir / file
            self.copy_into_container(hostpath, f"ctf_files/{file}")

    def teardown(self) -> None:
        self.stop_docker()

    def start_docker(self) -> None:
        cmd = [
            "docker",
            "run",
            "-d",
            "--rm",
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
            _run_docker_command([
                "docker",
                "exec",
                self.container,
                "mkdir",
                "-p",
                str(containerpath.parent),
            ])

        _run_docker_command([
            "docker",
            "cp",
            "-aq",
            str(hostpath),
            f"{self.container}:{containerpath}",
        ])
        return containerpath

    def stop_docker(self) -> None:
        if not self.container:
            return
        _run_docker_command(["docker", "stop", self.container])
        self.container = None

    @property
    def container_home(self) -> Path:
        return Path("/home/ctfplayer")
