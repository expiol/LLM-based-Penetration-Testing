"""Docker container lifecycle management for CTF challenges."""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows compatibility
    fcntl = None

from killchain_docker.processes import run_bounded_process
from nyuctf.challenge import CTFChallenge


_CONTAINER_CONFLICT_RE = re.compile(
    r"(address already in use"
    r"|is already in use by container"
    r"|Conflict\. The container name"
    r"|endpoint with name [^ ]+ already exists)",
    re.IGNORECASE,
)

COMPOSE_CHALLENGE_LOCK = Path(tempfile.gettempdir()) / "killchain_docker_compose_challenges.lock"


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
    return bool(getattr(challenge, "container", False) and _challenge_compose_path(challenge))


@contextmanager
def compose_challenge_run_lock(challenge: CTFChallenge):
    """Serialize compose-backed challenges across process workers."""
    if not _uses_compose(challenge) or fcntl is None:
        yield
        return

    COMPOSE_CHALLENGE_LOCK.parent.mkdir(parents=True, exist_ok=True)
    with COMPOSE_CHALLENGE_LOCK.open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"  [compose-lock] waiting for Docker service slot: {challenge.canonical_name}")
            fcntl.flock(handle, fcntl.LOCK_EX)
            print(f"  [compose-lock] acquired Docker service slot: {challenge.canonical_name}")
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
        run_bounded_process(
            ["docker", "compose", "-f", str(compose), "down", "--volumes", "--remove-orphans"],
            timeout_s=120,
            max_output_bytes=20_000,
        )
    except OSError:
        return


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
            if attempt >= attempts:
                break
            stderr_text = _subprocess_stream_text(exc.stderr)
            stdout_text = _subprocess_stream_text(exc.stdout)
            combined = "\n".join(part for part in (stderr_text, stdout_text) if part)
            conflict = bool(_CONTAINER_CONFLICT_RE.search(combined))
            print(
                f"  [start-retry] attempt {attempt}/{attempts} failed: "
                f"{'port/container conflict' if conflict else 'transient error'}; retrying..."
            )
            if debug and combined:
                print(combined[-600:])
            if conflict:
                docker_compose_down(challenge)
            else:
                time.sleep(5)
    assert last_exc is not None
    raise last_exc
