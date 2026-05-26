"""Bounded subprocess execution helpers."""

from __future__ import annotations

from dataclasses import dataclass
import os
import signal
import subprocess
import tempfile

DEFAULT_MAX_CAPTURE_BYTES = 1_000_000
DEFAULT_TERMINATION_GRACE_S = 2


@dataclass(frozen=True)
class BoundedProcessResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False


def _decode_limited_output(
    stream, *, max_bytes: int = DEFAULT_MAX_CAPTURE_BYTES
) -> str:
    stream.flush()
    size = stream.tell()
    stream.seek(0)
    if size <= max_bytes:
        return stream.read().decode("utf-8", errors="replace")

    head_size = max(0, max_bytes // 2)
    tail_size = max(0, max_bytes - head_size)
    head = stream.read(head_size)
    stream.seek(-tail_size, os.SEEK_END)
    tail = stream.read(tail_size)
    marker = (
        f"\n[output truncated: captured first {head_size} and last "
        f"{tail_size} bytes of {size}]\n"
    ).encode("utf-8")
    return (head + marker + tail).decode("utf-8", errors="replace")


def _terminate_process_group(
    proc: subprocess.Popen,
    *,
    grace_s: int = DEFAULT_TERMINATION_GRACE_S,
) -> None:
    if proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        proc.terminate()
    try:
        proc.wait(timeout=grace_s)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        proc.kill()
    proc.wait()


def run_bounded_process(
    argv: list[str],
    *,
    timeout_s: int | None,
    cwd: str | None = None,
    input_text: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_CAPTURE_BYTES,
) -> BoundedProcessResult:
    """Run a subprocess with bounded captured output and process-group timeout cleanup."""
    input_bytes = input_text.encode("utf-8") if input_text is not None else None
    with (
        tempfile.TemporaryFile() as stdout_file,
        tempfile.TemporaryFile() as stderr_file,
    ):
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            cwd=cwd,
            start_new_session=True,
        )

        timed_out = False
        try:
            timeout = timeout_s if timeout_s and timeout_s > 0 else None
            proc.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate_process_group(proc)
        except BaseException:
            _terminate_process_group(proc)
            raise

        stdout = _decode_limited_output(stdout_file, max_bytes=max_output_bytes)
        stderr = _decode_limited_output(stderr_file, max_bytes=max_output_bytes)
        if timed_out:
            stderr = f"{stderr}\n[timeout after {timeout_s}s]"
            return BoundedProcessResult(
                exit_code=-1,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )
        return BoundedProcessResult(
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
        )
