"""Machine-readable solver failure classification.

Generic, category-agnostic. We only distinguish failure modes that the
LLM can act on without us pretending we know the challenge:

* ``timeout`` — the runner killed the process.
* ``python_exception`` — stderr carries a Python traceback we can quote.
* ``runtime_error`` — non-zero exit code without a recognisable traceback.
* ``near_miss_garbled_flag`` — stdout produced flag-shaped but garbled text.
* ``exit_0_no_output`` — script exited cleanly but printed nothing.
* ``exit_0_no_flag`` — script printed output but none matched a real flag.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field


_TRACEBACK_LAST_LINE_RE = re.compile(
    r"^(?P<exc>[A-Z][A-Za-z0-9_]*Error|[A-Z][A-Za-z0-9_]*Exception|"
    r"SystemExit|KeyboardInterrupt|StopIteration|StopAsyncIteration)"
    r"(:\s*(?P<msg>.+))?$",
    re.MULTILINE,
)
_TRACEBACK_FRAME_RE = re.compile(
    r'^\s*File "(?P<path>[^"]+)", line (?P<lineno>\d+)(?:, in (?P<func>\S+))?',
    re.MULTILINE,
)


@dataclass(frozen=True)
class SolverFailureSignal:
    """Compact failure diagnosis for retry and recovery prompts."""

    failure_class: str
    error_fingerprint: str
    diagnosis: str
    must_avoid: list[str] = field(default_factory=list)
    required_checks: list[str] = field(default_factory=list)


class SolverFailureClassifier:
    """Classify solver failure into a generic, actionable signal."""

    @classmethod
    def classify(
        cls,
        *,
        attempt: int,
        returncode: int,
        stdout: str,
        stderr: str,
        timeout_s: int,
        near_miss: list[str] | None = None,
        previous_solver_code: str = "",
    ) -> SolverFailureSignal:
        near_miss = list(near_miss or [])
        combined = f"{stderr}\n{stdout}"
        lower = combined.lower()

        if returncode == -1 and ("timed out" in lower or "timeout after" in lower):
            return SolverFailureSignal(
                failure_class="timeout",
                error_fingerprint=f"timeout after {timeout_s}s",
                diagnosis=(
                    f"Attempt {attempt} timed out after {timeout_s}s. "
                    "Bound every loop, subprocess, and network call with a timeout, "
                    "and replace any potentially-unbounded iteration with a calibrated check."
                ),
                must_avoid=["Do not repeat unbounded loops or blocking calls."],
                required_checks=["Bound every loop / subprocess / network call with a timeout."],
            )

        if near_miss:
            return SolverFailureSignal(
                failure_class="near_miss_garbled_flag",
                error_fingerprint=f"near-miss flags {near_miss[:2]}",
                diagnosis=(
                    f"Attempt {attempt} produced flag-shaped but garbled text. "
                    "Fix the underlying transform; do not strip bytes to make the flag look right."
                ),
                must_avoid=["Do not post-process non-printable garbage into a flag."],
                required_checks=["Validate that recovered plaintext is printable before extracting flags."],
            )

        if returncode != 0:
            traceback_signal = cls._traceback_signal(
                attempt=attempt,
                stderr=stderr,
                previous_solver_code=previous_solver_code,
            )
            if traceback_signal is not None:
                return traceback_signal
            # No Python traceback found — could be a shell subprocess failure,
            # a network timeout, a binary returning non-zero, etc.  Fold a
            # stderr/stdout hash + leading sample into the fingerprint so
            # eight different "exit 1" failures don't all collapse onto the
            # same dedup key and starve the cross-chain memory of distinct
            # prior failures.
            sample_src = (stderr.strip() or stdout.strip())
            sample = sample_src[:80].replace("\n", " ")
            digest = hashlib.sha1(
                sample_src.encode("utf-8", "replace")
            ).hexdigest()[:8] if sample_src else "no-output"
            fingerprint = (
                f"exit {returncode} [{digest}] {sample}"[:200]
                if sample_src
                else f"exit {returncode} (no stderr/stdout)"
            )
            return SolverFailureSignal(
                failure_class="runtime_error",
                error_fingerprint=fingerprint,
                diagnosis=(
                    f"Attempt {attempt} crashed with exit code {returncode}. "
                    "Read stderr and address the concrete error before changing strategy."
                ),
                must_avoid=["Do not repeat the same runtime error."],
                required_checks=["Check stderr and handle missing files / dependencies explicitly."],
            )

        if not stdout.strip():
            return SolverFailureSignal(
                failure_class="exit_0_no_output",
                error_fingerprint="exit 0 with empty stdout",
                diagnosis=(
                    f"Attempt {attempt} exited 0 but printed nothing. "
                    "Print the derived flag token exactly once on its own line."
                ),
                must_avoid=["Do not exit silently on failed branches."],
                required_checks=["Print a single candidate only after it passes plausibility checks."],
            )

        # Fold a short hash + leading slice of the actual stdout into the
        # fingerprint so two different "clean run, no flag" attempts are
        # distinguishable in cross-chain memory.  Without this, every
        # crypto/parsing attempt that decoded different garbage (wrong
        # offset vs wrong byteorder vs wrong cipher) collapsed onto a
        # single ``"exit 0 without flag"`` entry and the dedup pass kept
        # only one — so the solver kept trying variants of the SAME bug
        # with no record of which approaches it had already explored.
        stdout_norm = stdout.strip()
        sample = stdout_norm[:80].replace("\n", " ")
        digest = hashlib.sha1(stdout_norm.encode("utf-8", "replace")).hexdigest()[:8]
        fingerprint = f"exit 0 no flag [{digest}] {sample}"[:200]
        return SolverFailureSignal(
            failure_class="exit_0_no_flag",
            error_fingerprint=fingerprint,
            diagnosis=(
                f"Attempt {attempt} exited 0 without a valid flag candidate. "
                "Switch to a different parsing / decoding strategy rather than re-tuning constants."
            ),
            must_avoid=["Do not repeat the same broad solver approach."],
            required_checks=["Add explicit candidate scoring and print only plausible answers."],
        )

    @staticmethod
    def _traceback_signal(
        *,
        attempt: int,
        stderr: str,
        previous_solver_code: str,
    ) -> SolverFailureSignal | None:
        exc_match = _TRACEBACK_LAST_LINE_RE.search(stderr)
        if exc_match is None:
            return None
        exc_type = exc_match.group("exc")
        exc_msg = (exc_match.group("msg") or "").strip()
        frame_matches = list(_TRACEBACK_FRAME_RE.finditer(stderr))
        offending = ""
        if frame_matches:
            last_frame = frame_matches[-1]
            lineno = int(last_frame.group("lineno"))
            func = last_frame.group("func") or "<module>"
            fingerprint = f"{exc_type}: {exc_msg} at line {lineno} in {func}".strip()
            lines = previous_solver_code.splitlines()
            if 1 <= lineno <= len(lines):
                offending = lines[lineno - 1].strip()
        else:
            fingerprint = f"{exc_type}: {exc_msg}".strip(": ")
        diagnosis = (
            f"Attempt {attempt} crashed with {fingerprint}. "
            "Fix that exact runtime error before changing strategy."
        )
        if offending:
            diagnosis += f" Offending line: ``{offending}``."
        return SolverFailureSignal(
            failure_class="python_exception",
            error_fingerprint=fingerprint,
            diagnosis=diagnosis,
            must_avoid=[f"Do not repeat {fingerprint}."],
            required_checks=["Add explicit file/dependency checks before use."],
        )
