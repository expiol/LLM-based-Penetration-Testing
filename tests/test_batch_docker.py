from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.batch.docker import (
    docker_compose_down,
    start_challenge_with_retry,
)
from killchain_docker.processes import BoundedProcessResult


class _FakeChallenge:
    canonical_name = "demo"
    container = True

    def __init__(self, challenge_dir: Path) -> None:
        self.challenge_dir = challenge_dir


class _RetryChallenge(_FakeChallenge):
    def __init__(self, challenge_dir: Path) -> None:
        super().__init__(challenge_dir)
        self.starts = 0

    def start_challenge_container(self) -> None:
        self.starts += 1
        if self.starts == 1:
            raise subprocess.CalledProcessError(
                returncode=1,
                cmd=["docker", "run"],
                stderr="temporary registry failure",
            )


class _PortConflictChallenge(_FakeChallenge):
    def __init__(self, challenge_dir: Path) -> None:
        super().__init__(challenge_dir)
        self.starts = 0

    def start_challenge_container(self) -> None:
        self.starts += 1
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["docker", "compose", "up"],
            stderr=(
                "Error response from daemon: ports are not available: "
                "listen tcp 0.0.0.0:5000: bind: address already in use"
            ),
        )


class _LegacyPinBuildFailureChallenge(_FakeChallenge):
    def __init__(self, challenge_dir: Path) -> None:
        super().__init__(challenge_dir)
        self.starts = 0

    def start_challenge_container(self) -> None:
        self.starts += 1
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["docker", "compose", "up"],
            stderr=(
                "Dockerfile:13\n"
                "RUN pip install -r pip-freeze.txt\n"
                "ERROR: Could not find a version that satisfies the requirement "
                "cmake==3.15.3\n"
                "ERROR: No matching distribution found for cmake==3.15.3"
            ),
        )


class _TruncatedLegacyPinBuildFailureChallenge(_FakeChallenge):
    def __init__(self, challenge_dir: Path) -> None:
        super().__init__(challenge_dir)
        self.starts = 0

    def start_challenge_container(self) -> None:
        self.starts += 1
        raise subprocess.CalledProcessError(
            returncode=1,
            cmd=["docker", "compose", "up"],
            stderr=(
                "Dockerfile:13\n"
                "RUN pip install -r pip-freeze.txt\n"
                "failed to solve: process \"/bin/sh -c pip install -r "
                "pip-freeze.txt\" did not complete successfully: exit code: 1"
            ),
        )


class DockerLifecycleTests(unittest.TestCase):
    def test_docker_compose_down_runs_cleanup_for_compose_challenge(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            challenge = _FakeChallenge(Path(tmp))

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                return_value=BoundedProcessResult(exit_code=0, stdout="", stderr=""),
            ) as run_process:
                docker_compose_down(challenge)  # type: ignore[arg-type]

            command = run_process.call_args.args[0]
            self.assertEqual(command[:3], ["docker", "compose", "-f"])
            self.assertEqual(command[3], str(compose))
            self.assertIn("down", command)
            self.assertIn("--remove-orphans", command)

    def test_docker_compose_down_logs_nonzero_cleanup_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            challenge = _FakeChallenge(Path(tmp))

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                return_value=BoundedProcessResult(
                    exit_code=1, stdout="", stderr="cleanup failed"
                ),
            ):
                with self.assertLogs(
                    "killchain_docker.batch.docker", level="WARNING"
                ) as captured:
                    docker_compose_down(challenge)  # type: ignore[arg-type]

            self.assertEqual(len(captured.records), 1)
            record = captured.records[0]
            self.assertEqual(record.challenge, "demo")
            self.assertEqual(record.compose_path, str(compose))
            self.assertEqual(record.exit_code, 1)
            self.assertEqual(record.stderr_tail, "cleanup failed")

    def test_docker_compose_down_skips_challenges_without_compose_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            challenge = _FakeChallenge(Path(tmp))

            with patch(
                "killchain_docker.batch.docker.run_bounded_process"
            ) as run_process:
                docker_compose_down(challenge)  # type: ignore[arg-type]

            run_process.assert_not_called()

    def test_start_retry_warning_includes_context_and_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            challenge = _RetryChallenge(Path(tmp))

            with (
                patch("killchain_docker.batch.docker.time.sleep"),
                self.assertLogs(
                    "killchain_docker.batch.docker", level="WARNING"
                ) as captured,
            ):
                start_challenge_with_retry(challenge, attempts=2)

            self.assertEqual(challenge.starts, 2)
            self.assertEqual(len(captured.records), 1)
            record = captured.records[0]
            self.assertEqual(record.challenge, "demo")
            self.assertEqual(record.attempt, 1)
            self.assertEqual(record.attempts, 2)
            self.assertEqual(record.reason, "transient error")
            self.assertTrue(any("Traceback" in message for message in captured.output))

    def test_host_port_conflict_retries_compose_without_host_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            compose = Path(tmp) / "docker-compose.yml"
            compose.write_text("services: {}\n", encoding="utf-8")
            challenge = _PortConflictChallenge(Path(tmp))
            compose_config = {
                "name": "demo",
                "services": {
                    "server": {
                        "image": "example/service",
                        "ports": [
                            {
                                "target": 5000,
                                "published": "5000",
                                "protocol": "tcp",
                            }
                        ],
                    }
                },
            }
            generated_configs: list[dict] = []

            def fake_run(command: list[str], **_kwargs) -> BoundedProcessResult:
                if "down" in command:
                    return BoundedProcessResult(exit_code=0, stdout="", stderr="")
                if "config" in command:
                    return BoundedProcessResult(
                        exit_code=0,
                        stdout=json.dumps(compose_config),
                        stderr="",
                    )
                if "up" in command:
                    generated_configs.append(
                        json.loads(Path(command[5]).read_text(encoding="utf-8"))
                    )
                    return BoundedProcessResult(exit_code=0, stdout="", stderr="")
                raise AssertionError(f"unexpected command: {command}")

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                side_effect=fake_run,
            ):
                start_challenge_with_retry(challenge, attempts=2)  # type: ignore[arg-type]

            self.assertEqual(challenge.starts, 1)
            self.assertEqual(len(generated_configs), 1)
            service = generated_configs[0]["services"]["server"]
            self.assertNotIn("ports", service)
            self.assertEqual(service["expose"], ["5000"])

    def test_legacy_python_pin_build_failure_uses_temporary_patched_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compose = root / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  client:\n"
                "    build: ./client\n",
                encoding="utf-8",
            )
            client = root / "client"
            client.mkdir()
            requirements = client / "pip-freeze.txt"
            requirements.write_text("cmake==3.15.3\nFlask==1.1.1\n", encoding="utf-8")
            challenge = _LegacyPinBuildFailureChallenge(root)
            patched_requirements: list[str] = []

            def fake_run(command: list[str], **_kwargs) -> BoundedProcessResult:
                self.assertEqual(command[:4], ["docker", "compose", "--project-name", root.name])
                patched_compose = Path(command[5])
                patched_requirements.append(
                    (patched_compose.parent / "client" / "pip-freeze.txt").read_text(
                        encoding="utf-8"
                    )
                )
                return BoundedProcessResult(exit_code=0, stdout="", stderr="")

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                side_effect=fake_run,
            ):
                start_challenge_with_retry(challenge, attempts=2)  # type: ignore[arg-type]

            self.assertEqual(challenge.starts, 1)
            self.assertEqual(patched_requirements, ["cmake==3.15.3.post1\nFlask==1.1.1\n"])
            self.assertEqual(
                requirements.read_text(encoding="utf-8"),
                "cmake==3.15.3\nFlask==1.1.1\n",
            )

    def test_truncated_python_pin_build_failure_checks_compose_context(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compose = root / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  client:\n"
                "    build: ./client\n",
                encoding="utf-8",
            )
            client = root / "client"
            client.mkdir()
            dockerfile = client / "Dockerfile"
            dockerfile.write_text(
                "FROM python:3.6\n"
                "COPY pip-freeze.txt /app/pip-freeze.txt\n"
                "RUN pip install -r pip-freeze.txt\n",
                encoding="utf-8",
            )
            requirements = client / "pip-freeze.txt"
            requirements.write_text(
                "cmake==3.15.3\nscikit-build==0.10.0\nFlask==1.1.1\n",
                encoding="utf-8",
            )
            challenge = _TruncatedLegacyPinBuildFailureChallenge(root)
            patched_requirements: list[str] = []
            patched_dockerfiles: list[str] = []

            def fake_run(command: list[str], **_kwargs) -> BoundedProcessResult:
                patched_compose = Path(command[5])
                patched_requirements.append(
                    (patched_compose.parent / "client" / "pip-freeze.txt").read_text(
                        encoding="utf-8"
                    )
                )
                patched_dockerfiles.append(
                    (patched_compose.parent / "client" / "Dockerfile").read_text(
                        encoding="utf-8"
                    )
                )
                return BoundedProcessResult(exit_code=0, stdout="", stderr="")

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                side_effect=fake_run,
            ):
                start_challenge_with_retry(challenge, attempts=2)  # type: ignore[arg-type]

            self.assertEqual(challenge.starts, 1)
            self.assertEqual(
                patched_requirements,
                ["cmake==3.15.3.post1\nscikit-build==0.10.0\nFlask==1.1.1\n"],
            )
            self.assertIn(
                "RUN pip install scikit-build==0.10.0\n"
                "RUN pip install -r pip-freeze.txt",
                patched_dockerfiles[0],
            )
            self.assertEqual(
                requirements.read_text(encoding="utf-8"),
                "cmake==3.15.3\nscikit-build==0.10.0\nFlask==1.1.1\n",
            )
            self.assertNotIn(
                "RUN pip install scikit-build==0.10.0",
                dockerfile.read_text(encoding="utf-8"),
            )

    def test_system_package_install_removes_redundant_legacy_python_pin(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compose = root / "docker-compose.yml"
            compose.write_text(
                "services:\n"
                "  client:\n"
                "    build: ./client\n",
                encoding="utf-8",
            )
            client = root / "client"
            client.mkdir()
            dockerfile = client / "Dockerfile"
            dockerfile.write_text(
                "FROM python:3.6\n"
                "RUN apt-get update && apt-get install -y build-essential cmake\n"
                "COPY pip-freeze.txt /app/pip-freeze.txt\n"
                "RUN pip install -r pip-freeze.txt\n",
                encoding="utf-8",
            )
            requirements = client / "pip-freeze.txt"
            requirements.write_text(
                "cmake==3.15.3\nscikit-build==0.10.0\nFlask==1.1.1\n",
                encoding="utf-8",
            )
            challenge = _TruncatedLegacyPinBuildFailureChallenge(root)
            patched_requirements: list[str] = []

            def fake_run(command: list[str], **_kwargs) -> BoundedProcessResult:
                patched_compose = Path(command[5])
                patched_requirements.append(
                    (patched_compose.parent / "client" / "pip-freeze.txt").read_text(
                        encoding="utf-8"
                    )
                )
                return BoundedProcessResult(exit_code=0, stdout="", stderr="")

            with patch(
                "killchain_docker.batch.docker.run_bounded_process",
                side_effect=fake_run,
            ):
                start_challenge_with_retry(challenge, attempts=2)  # type: ignore[arg-type]

            self.assertEqual(
                patched_requirements,
                ["scikit-build==0.10.0\nFlask==1.1.1\n"],
            )
            self.assertEqual(
                requirements.read_text(encoding="utf-8"),
                "cmake==3.15.3\nscikit-build==0.10.0\nFlask==1.1.1\n",
            )


if __name__ == "__main__":
    unittest.main()
