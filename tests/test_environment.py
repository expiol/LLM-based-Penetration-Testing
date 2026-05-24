from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from killchain_docker.environment import CTFEnvironment, cleanup_stale_managed_containers


class _Challenge:
    canonical_name = "demo challenge"
    files: list[str] = []
    challenge_dir = Path("/tmp/demo")


class EnvironmentTests(unittest.TestCase):
    def test_start_docker_labels_managed_container(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(command)
            return "container-id"

        env = CTFEnvironment(_Challenge(), "ctfenv:latest", "ctfnet")

        with (
            patch("killchain_docker.environment.cleanup_stale_managed_containers") as cleanup,
            patch("killchain_docker.environment._run_docker_command", side_effect=fake_run),
        ):
            env.start_docker()

        cleanup.assert_called_once_with()
        self.assertEqual(env.container, "container-id")
        command = commands[0]
        self.assertNotIn("--rm", command)
        self.assertIn("--restart", command)
        self.assertIn("on-failure:3", command)
        self.assertIn("--name", command)
        name = command[command.index("--name") + 1]
        self.assertTrue(name.startswith("killchain-exec-"))
        self.assertIn("--label", command)
        self.assertIn("killchain_docker.managed=true", command)
        self.assertIn("killchain_docker.challenge=demo_challenge", command)
        self.assertTrue(any(item.startswith("killchain_docker.owner_pid=") for item in command))

    def test_cleanup_stale_managed_containers_stops_dead_owner(self) -> None:
        commands: list[list[str]] = []

        def fake_run(command: list[str]) -> str:
            commands.append(command)
            if command[:2] == ["docker", "ps"]:
                return "dead-container\t123\nlive-container\t456\n"
            return command[-1]

        def owner_alive(pid: str) -> bool:
            return pid == "456"

        with (
            patch("killchain_docker.environment._run_docker_command", side_effect=fake_run),
            patch("killchain_docker.environment._owner_pid_alive", side_effect=owner_alive),
        ):
            cleanup_stale_managed_containers()

        self.assertEqual(commands[0][:2], ["docker", "ps"])
        self.assertIn("-a", commands[0])
        self.assertIn("label=killchain_docker.managed=true", commands[0])
        self.assertIn(["docker", "rm", "-f", "dead-container"], commands)
        self.assertNotIn(["docker", "rm", "-f", "live-container"], commands)


if __name__ == "__main__":
    unittest.main()
