"""Docker container lifecycle management for CTF challenges."""

from __future__ import annotations

import json
import fcntl
import os
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

from killchain_docker.logging_utils import get_logger
from killchain_docker.processes import run_bounded_process
from nyuctf.challenge import CTFChallenge


LOGGER = get_logger(__name__)


_CONTAINER_CONFLICT_RE = re.compile(
    r"(address already in use"
    r"|ports are not available"
    r"|port is already allocated"
    r"|is already in use by container"
    r"|Conflict\. The container name"
    r"|endpoint with name [^ ]+ already exists)",
    re.IGNORECASE,
)
_HOST_PORT_CONFLICT_RE = re.compile(
    r"(ports are not available|port is already allocated|bind: address already in use|listen tcp .*address already in use)",
    re.IGNORECASE,
)
_PYPI_PIN_COMPAT_REWRITES = {
    "cmake==3.15.3": "cmake==3.15.3.post1",
}
_SYSTEM_PACKAGE_PIN_REMOVALS = {
    "cmake": re.compile(r"(?im)^\s*cmake==[^\s#]+\s*(?:#.*)?\n?"),
}
_PYTHON_REQUIREMENT_FILENAMES = {
    "requirements.txt",
    "pip-freeze.txt",
    "constraints.txt",
}
_PYTHON_BUILD_BACKEND_REQUIREMENTS = {
    "scikit-build": re.compile(
        r"(?im)^\s*(scikit-build(?:==[^\s#]+)?)\s*(?:#.*)?$"
    ),
}

COMPOSE_CHALLENGE_LOCK = (
    Path(tempfile.gettempdir()) / "killchain_docker_compose_challenges.lock"
)


def _subprocess_stream_text(chunk: str | bytes | None) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace").strip()
    return str(chunk).strip()


def _challenge_compose_path(challenge: CTFChallenge) -> Path | None:
    candidate = getattr(challenge, "challenge_dir", None)
    if candidate is None:
        return None
    compose = Path(candidate) / "docker-compose.yml"
    return compose if compose.exists() else None


def _uses_compose(challenge: CTFChallenge) -> bool:
    return bool(
        getattr(challenge, "container", False) and _challenge_compose_path(challenge)
    )


@contextmanager
def compose_challenge_run_lock(challenge: CTFChallenge):
    """Serialize compose-backed challenges across process workers."""
    if not _uses_compose(challenge):
        yield
        return

    COMPOSE_CHALLENGE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with COMPOSE_CHALLENGE_LOCK.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            LOGGER.info(
                "waiting for Docker service slot",
                extra={"challenge": challenge.canonical_name},
            )
            fcntl.flock(handle, fcntl.LOCK_EX)
            LOGGER.info(
                "acquired Docker service slot",
                extra={"challenge": challenge.canonical_name},
            )
        handle.seek(0)
        handle.truncate()
        handle.write(f"{os.getpid()} {challenge.canonical_name}\n")
        handle.flush()
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def docker_compose_down(challenge: CTFChallenge) -> None:
    """Best-effort cleanup so the next ``up`` doesn't hit name/port conflicts."""
    compose = _challenge_compose_path(challenge)
    if compose is None:
        return
    try:
        result = run_bounded_process(
            [
                "docker",
                "compose",
                "-f",
                str(compose),
                "down",
                "--volumes",
                "--remove-orphans",
            ],
            timeout_s=120,
            max_output_bytes=20_000,
        )
    except OSError:
        LOGGER.debug(
            "Docker compose cleanup could not start",
            exc_info=True,
            extra={"challenge": challenge.canonical_name, "compose_path": str(compose)},
        )
        return
    if result.exit_code != 0:
        LOGGER.warning(
            "Docker compose cleanup failed",
            extra={
                "challenge": challenge.canonical_name,
                "compose_path": str(compose),
                "exit_code": result.exit_code,
                "stderr_tail": result.stderr[-600:],
            },
        )


def _compose_config_json(compose: Path) -> dict:
    command = ["docker", "compose", "-f", str(compose), "config", "--format", "json"]
    result = run_bounded_process(
        command,
        timeout_s=120,
        max_output_bytes=200_000,
    )
    if result.exit_code != 0:
        raise subprocess.CalledProcessError(
            result.exit_code,
            command,
            output=result.stdout,
            stderr=result.stderr,
        )
    return json.loads(result.stdout)


def _without_host_port_bindings(config: dict) -> tuple[dict, bool]:
    """Return a compose config that keeps internal networking but drops host binds."""
    services = config.get("services")
    if not isinstance(services, dict):
        return config, False

    changed = False
    for service in services.values():
        if not isinstance(service, dict):
            continue
        ports = service.pop("ports", None)
        if not ports:
            continue
        changed = True
        exposed = {str(item) for item in service.get("expose") or [] if item}
        for item in ports:
            if not isinstance(item, dict):
                continue
            target = item.get("target")
            if target:
                protocol = str(item.get("protocol") or "").strip().lower()
                exposed.add(
                    f"{target}/{protocol}"
                    if protocol and protocol != "tcp"
                    else str(target)
                )
        if exposed:
            service["expose"] = sorted(exposed)
    return config, changed


def _start_compose_without_host_ports(challenge: CTFChallenge) -> bool:
    compose = _challenge_compose_path(challenge)
    if compose is None:
        return False

    config, changed = _without_host_port_bindings(_compose_config_json(compose))
    if not changed:
        return False

    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        suffix=".compose.json",
        prefix=f"{challenge.canonical_name}-",
        delete=False,
    ) as handle:
        json.dump(config, handle)
        override_path = Path(handle.name)

    try:
        command = [
                "docker",
                "compose",
                "--project-name",
                compose.parent.name,
                "-f",
                str(override_path),
                "up",
                "-d",
                "--force-recreate",
            ]
        result = run_bounded_process(
            command,
            timeout_s=180,
            max_output_bytes=80_000,
        )
    finally:
        try:
            override_path.unlink()
        except OSError:
            LOGGER.debug(
                "failed to remove temporary compose override",
                exc_info=True,
                extra={
                    "challenge": challenge.canonical_name,
                    "override_path": str(override_path),
                },
            )

    if result.exit_code != 0:
        raise subprocess.CalledProcessError(
            result.exit_code,
            command,
            output=result.stdout,
            stderr=result.stderr,
        )
    LOGGER.info(
        "started compose challenge without host port bindings",
        extra={"challenge": challenge.canonical_name, "compose_path": str(compose)},
    )
    return True


def _rewrite_legacy_python_pins(root: Path) -> bool:
    changed = False
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in _PYTHON_REQUIREMENT_FILENAMES:
            continue
        try:
            original = path.read_text(encoding="utf-8")
        except OSError:
            continue
        updated = original
        for old, new in _PYPI_PIN_COMPAT_REWRITES.items():
            updated = updated.replace(old, new)
        if updated == original:
            continue
        path.write_text(updated, encoding="utf-8")
        changed = True
    return changed


def _dockerfile_installs_system_package(dockerfile: Path, package: str) -> bool:
    text = _read_text(dockerfile)
    if text is None:
        return False
    pattern = re.compile(
        rf"(?is)\b(?:apt-get|apk|yum|dnf)\s+.*\binstall\b[^\n]*\b{re.escape(package)}\b"
    )
    return bool(pattern.search(text))


def _remove_system_provided_python_pins(root: Path) -> bool:
    changed = False
    for dockerfile in root.rglob("Dockerfile"):
        if not dockerfile.is_file():
            continue
        system_packages = [
            package
            for package in _SYSTEM_PACKAGE_PIN_REMOVALS
            if _dockerfile_installs_system_package(dockerfile, package)
        ]
        if not system_packages:
            continue
        for requirements in dockerfile.parent.iterdir():
            if (
                not requirements.is_file()
                or requirements.name not in _PYTHON_REQUIREMENT_FILENAMES
            ):
                continue
            original = _read_text(requirements)
            if original is None:
                continue
            updated = original
            for package in system_packages:
                updated = _SYSTEM_PACKAGE_PIN_REMOVALS[package].sub("", updated)
            if updated != original and _write_text(requirements, updated):
                changed = True
    return changed


def _read_text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _write_text(path: Path, text: str) -> bool:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError:
        return False
    return True


def _has_legacy_python_pins(root: Path) -> bool:
    for path in root.rglob("*"):
        if not path.is_file() or path.name not in _PYTHON_REQUIREMENT_FILENAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lowered = text.lower()
        if any(pin.lower() in lowered for pin in _PYPI_PIN_COMPAT_REWRITES):
            return True
    return False


def _requirements_referenced_build_backends(requirements: Path) -> list[str]:
    text = _read_text(requirements)
    if text is None:
        return []
    requirements_found: list[str] = []
    for pattern in _PYTHON_BUILD_BACKEND_REQUIREMENTS.values():
        match = pattern.search(text)
        if match:
            requirements_found.append(match.group(1))
    return requirements_found


def _inject_python_build_backend_installs(root: Path) -> bool:
    changed = False
    for dockerfile in root.rglob("Dockerfile"):
        if not dockerfile.is_file():
            continue
        original = _read_text(dockerfile)
        if original is None:
            continue
        lines = original.splitlines(keepends=True)
        updated: list[str] = []
        file_changed = False
        for line in lines:
            match = re.match(r"(?i)^(\s*RUN\s+pip\s+install\s+-r\s+)(\S+)(.*)$", line)
            if match:
                req_name = match.group(2).strip().strip("'\"")
                requirements = (dockerfile.parent / req_name).resolve()
                backends = _requirements_referenced_build_backends(requirements)
                for backend in backends:
                    install_line = f"RUN pip install {backend}\n"
                    if install_line not in original and install_line not in updated:
                        updated.append(install_line)
                        file_changed = True
            updated.append(line)
        if file_changed and _write_text(dockerfile, "".join(updated)):
            changed = True
    return changed


def _copy_compose_context_for_legacy_pins(compose: Path) -> Path | None:
    challenge_dir = compose.parent
    with tempfile.TemporaryDirectory(
        prefix=f"{challenge_dir.name}-compose-compat-"
    ) as tmp:
        tmp_path = Path(tmp)
        build_root = tmp_path / "context"
        try:
            shutil.copytree(
                challenge_dir,
                build_root,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    ".autopentest_artifacts",
                    "node_modules",
                ),
            )
        except OSError:
            LOGGER.debug(
                "failed to copy compose build context",
                exc_info=True,
                extra={"compose_path": str(compose)},
            )
            return None
        removed_system_pins = _remove_system_provided_python_pins(build_root)
        rewritten_pins = _rewrite_legacy_python_pins(build_root)
        if not (removed_system_pins or rewritten_pins):
            return None
        _inject_python_build_backend_installs(build_root)
        keep_path = Path(
            tempfile.mkdtemp(prefix=f"{challenge_dir.name}-compose-compat-run-")
        )
        shutil.copytree(build_root, keep_path, dirs_exist_ok=True)
        return keep_path


def _start_compose_with_legacy_pin_compat(challenge: CTFChallenge) -> bool:
    compose = _challenge_compose_path(challenge)
    if compose is None:
        return False
    patched_root = _copy_compose_context_for_legacy_pins(compose)
    if patched_root is None:
        return False
    try:
        command = [
                "docker",
                "compose",
                "--project-name",
                compose.parent.name,
                "-f",
                str(patched_root / "docker-compose.yml"),
                "up",
                "-d",
                "--force-recreate",
            ]
        result = run_bounded_process(
            command,
            timeout_s=300,
            max_output_bytes=120_000,
        )
    finally:
        shutil.rmtree(patched_root, ignore_errors=True)
    if result.exit_code != 0:
        raise subprocess.CalledProcessError(
            result.exit_code,
            command,
            output=result.stdout,
            stderr=result.stderr,
        )
    LOGGER.info(
        "started compose challenge with legacy Python package pin compatibility",
        extra={"challenge": challenge.canonical_name, "compose_path": str(compose)},
    )
    return True


def _is_legacy_python_pin_build_failure(
    exc: subprocess.CalledProcessError,
    challenge: CTFChallenge,
) -> bool:
    combined = "\n".join(
        part
        for part in (_subprocess_stream_text(exc.stderr), _subprocess_stream_text(exc.stdout))
        if part
    ).lower()
    if "pip install" not in combined:
        return False
    if "no matching distribution found" in combined and any(
        pin.lower() in combined for pin in _PYPI_PIN_COMPAT_REWRITES
    ):
        return True
    if not any(
        marker in combined
        for marker in ("dockerfile:", "failed to solve", "process \"/bin/sh -c")
    ):
        return False
    compose = _challenge_compose_path(challenge)
    if compose is None:
        return False
    return _has_legacy_python_pins(compose.parent)


def start_challenge_with_retry(
    challenge: CTFChallenge,
    *,
    attempts: int = 3,
    debug: bool = False,
) -> None:
    """Start the challenge container, retrying past port/registry hiccups."""
    last_exc: subprocess.CalledProcessError | None = None
    for attempt in range(1, attempts + 1):
        try:
            challenge.start_challenge_container()
            return
        except subprocess.CalledProcessError as exc:
            last_exc = exc
            stderr_text = _subprocess_stream_text(exc.stderr)
            stdout_text = _subprocess_stream_text(exc.stdout)
            combined = "\n".join(part for part in (stderr_text, stdout_text) if part)
            conflict = bool(_CONTAINER_CONFLICT_RE.search(combined))
            LOGGER.warning(
                "challenge container start failed; retrying",
                exc_info=True,
                extra={
                    "challenge": challenge.canonical_name,
                    "attempt": attempt,
                    "attempts": attempts,
                    "reason": "port/container conflict"
                    if conflict
                    else "transient error",
                },
            )
            if debug and combined:
                LOGGER.debug(
                    "challenge container start output tail",
                    extra={
                        "challenge": challenge.canonical_name,
                        "output_tail": combined[-600:],
                    },
                )
            if conflict:
                docker_compose_down(challenge)
                if _HOST_PORT_CONFLICT_RE.search(combined):
                    try:
                        if _start_compose_without_host_ports(challenge):
                            return
                    except (
                        OSError,
                        json.JSONDecodeError,
                        subprocess.CalledProcessError,
                    ):
                        LOGGER.warning(
                            "host-port-free compose start failed; retrying original start",
                            exc_info=True,
                            extra={
                                "challenge": challenge.canonical_name,
                                "attempt": attempt,
                            },
                        )
            elif _is_legacy_python_pin_build_failure(exc, challenge):
                try:
                    if _start_compose_with_legacy_pin_compat(challenge):
                        return
                except (OSError, subprocess.CalledProcessError):
                    LOGGER.warning(
                        "legacy Python pin compatibility compose start failed; retrying original start",
                        exc_info=True,
                        extra={
                            "challenge": challenge.canonical_name,
                            "attempt": attempt,
                        },
                    )
            else:
                time.sleep(5)
            if attempt >= attempts:
                break
    assert last_exc is not None
    raise last_exc
