"""NYU CTF docker environment helpers."""

from __future__ import annotations

import subprocess
from pathlib import Path

from nyuctf.challenge import CTFChallenge


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
        output = subprocess.run(cmd, check=True, capture_output=True, text=True)
        self.container = output.stdout.strip()

    def copy_into_container(self, hostpath: str | Path, filename: str | Path) -> Path:
        if self.container is None:
            raise RuntimeError("container is not running")

        hostpath = Path(hostpath)
        if Path(filename).is_absolute():
            containerpath = Path(filename)
        else:
            containerpath = self.container_home / filename
            subprocess.run(
                ["docker", "exec", self.container, "mkdir", "-p", str(containerpath.parent)],
                check=True,
                capture_output=True,
                text=True,
            )

        subprocess.run(
            ["docker", "cp", "-aq", str(hostpath), f"{self.container}:{containerpath}"],
            check=True,
            capture_output=True,
            text=True,
        )
        return containerpath

    def stop_docker(self) -> None:
        if not self.container:
            return
        subprocess.run(["docker", "stop", self.container], check=True, capture_output=True, text=True)
        self.container = None

    @property
    def container_home(self) -> Path:
        return Path("/home/ctfplayer")
