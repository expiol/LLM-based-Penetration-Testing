"""Batch execution: single-challenge runner and multi-challenge orchestration."""

from __future__ import annotations

import argparse
import json
import time
import traceback
import subprocess
from pathlib import Path
from typing import Any

from nyuctf.challenge import CTFChallenge

from killchain_docker.batch.dataset import (
    challenge_metadata,
    derive_authorized_scope,
    derive_objective,
    estimate_max_cycles,
)
from killchain_docker.batch.docker import (
    compose_challenge_run_lock,
    start_challenge_with_retry,
)
from killchain_docker.controller import RunConfig, run_assessment
from killchain_docker.environment import CTFEnvironment
from killchain_docker.llm import LLMClientError, build_llm_client_from_env
from killchain_docker.tools import build_execution_plane


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SENSITIVE_KEYS = frozenset({"api_key", "authorization", "token", "secret", "password"})
_TOKEN_USAGE_KEYS = ("llm_calls", "prompt_tokens", "completion_tokens", "total_tokens")
_LEGACY_LLM_ENV_KEYS = (
    "AUTOPENTEST_LLM_MODE", "AUTOPENTEST_LLM_CONFIG_PATH", "AUTOPENTEST_LLM_PROVIDER",
    "AUTOPENTEST_LLM_BASE_URL", "AUTOPENTEST_LLM_MODEL", "AUTOPENTEST_LLM_API_KEY",
    "AUTOPENTEST_LLM_SCHEMA_MODELS", "AUTOPENTEST_LLM_TIMEOUT_S",
    "AUTOPENTEST_LLM_MAX_RETRIES", "AUTOPENTEST_LLM_MAX_COMPLETION_TOKENS",
)
_API_BALANCE_PATTERNS = [
    "insufficient_quota", "insufficient balance", "Arrearage", "billing",
    "exceeded your current quota", "account has been suspended", "rate_limit_exceeded",
    "You exceeded your current quota", "余额不足", "欠费", "账户余额",
]


def _mask_secret(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-4:]}"


def _sanitize_for_log(value: Any, *, key: str | None = None) -> Any:
    lowered_key = (key or "").lower()
    if lowered_key in _SENSITIVE_KEYS:
        return _mask_secret(value)
    if isinstance(value, dict):
        return {k: _sanitize_for_log(v, key=k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_log(item, key=key) for item in value]
    return value


def _token_usage(value: Any) -> dict[str, int]:
    payload = value if isinstance(value, dict) else {}
    return {key: int(payload.get(key) or 0) for key in _TOKEN_USAGE_KEYS}


def _is_api_balance_error(exc: Exception) -> bool:
    exc_str = str(exc).lower()
    exc_type = type(exc).__name__
    if "RateLimit" in exc_type or "AuthenticationError" in exc_type:
        return True
    return any(p.lower() in exc_str for p in _API_BALANCE_PATTERNS)


def _configure_llm_environment() -> None:
    import os
    for key in _LEGACY_LLM_ENV_KEYS:
        os.environ.pop(key, None)


def _subprocess_stream_text(chunk: str | bytes | None) -> str:
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", errors="replace").strip()
    return str(chunk).strip()


def _called_process_message(exc: subprocess.CalledProcessError) -> str:
    message = str(exc)
    err_out = _subprocess_stream_text(exc.stderr)
    std_out = _subprocess_stream_text(exc.stdout)
    if err_out:
        return f"{message}\nstderr:\n{err_out}"
    if std_out:
        return f"{message}\nstdout:\n{std_out}"
    return message


def write_log(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def resolve_experiment_logdir(args: argparse.Namespace) -> Path:
    logdir = Path(args.logdir).expanduser().resolve()
    suffix = "_".join(
        part for part in (
            getattr(args, "name", None),
            f"round{args.index}" if getattr(args, "index", None) else None,
        ) if part
    )
    logdir = logdir / suffix if suffix else logdir
    logdir.mkdir(parents=True, exist_ok=True)
    return logdir


def resolve_logfile(args: argparse.Namespace, challenge: CTFChallenge) -> Path:
    return resolve_experiment_logdir(args) / f"{challenge.canonical_name}.json"


def resolve_output_root(args: argparse.Namespace, challenge: CTFChallenge, logfile: Path) -> Path:
    if args.output_root:
        return Path(args.output_root).expanduser().resolve()
    return logfile.parent / "artifacts" / challenge.canonical_name


# ---------------------------------------------------------------------------
# Single challenge execution
# ---------------------------------------------------------------------------

def run_single_challenge(args: argparse.Namespace, challenge: CTFChallenge) -> dict[str, Any]:
    """Run a single challenge and return the result dict."""
    logfile = resolve_logfile(args, challenge)

    if logfile.exists() and args.skip_exist:
        print(f"  [skip] {challenge.canonical_name} — log exists: {logfile}")
        return {
            "challenge": challenge.canonical_name, "status": "skipped",
            "solved": False, "api_error": False, "llm_error": False,
        }

    with compose_challenge_run_lock(challenge):
        return _run_single_challenge_inner(args, challenge, logfile)


def _run_single_challenge_inner(
    args: argparse.Namespace, challenge: CTFChallenge, logfile: Path,
) -> dict[str, Any]:
    authorized_scope = args.scope or derive_authorized_scope(challenge)
    objective = args.objective or derive_objective(challenge, authorized_scope)
    output_root = resolve_output_root(args, challenge, logfile)

    effective_max_cycles = args.max_cycles
    if args.max_cycles == 8:
        effective_max_cycles = estimate_max_cycles(challenge, authorized_scope, base_cycles=8)

    config = RunConfig(
        objective=objective,
        authorized_scope=authorized_scope,
        output_root=str(output_root),
        max_cycles=effective_max_cycles,
        quiet=args.quiet,
        metadata={"challenge": challenge_metadata(challenge)},
    )

    environment = CTFEnvironment(challenge, args.container_image, args.container_network)
    started_at = time.time()
    artifacts = None
    error_payload = None
    traceback_text = None
    solved = False
    is_api_error = False
    is_llm_error = False
    interrupted = False

    try:
        _configure_llm_environment()
        llm_client = build_llm_client_from_env(preflight=True)
        start_challenge_with_retry(challenge, debug=args.debug)
        environment.setup()
        if not environment.container:
            raise RuntimeError("environment container did not start")

        execution_plane = build_execution_plane(
            argv_prefix=["docker", "exec", environment.container],
            python_executable="python3",
        )
        artifacts = run_assessment(
            config, execution_plane=execution_plane,
            expected_flag=challenge.flag, llm_client=llm_client,
        )
    except (KeyboardInterrupt, SystemExit) as exc:
        interrupted = True
        error_payload = {"type": type(exc).__name__, "message": f"Run interrupted by {type(exc).__name__}"}
        try:
            traceback_text = traceback.format_exc()
        except Exception:
            traceback_text = error_payload["message"]
    except Exception as exc:
        message = _called_process_message(exc) if isinstance(exc, subprocess.CalledProcessError) else str(exc)
        error_payload = {"type": type(exc).__name__, "message": message}
        try:
            traceback_text = traceback.format_exc()
        except Exception:
            traceback_text = f"{type(exc).__name__}: {exc}"
        is_llm_error = isinstance(exc, LLMClientError)
        is_api_error = is_llm_error or _is_api_balance_error(exc)
    finally:
        try:
            environment.teardown()
        except Exception:
            pass
        try:
            challenge.stop_challenge_container()
        except Exception:
            pass

    ended_at = time.time()
    summary_payload = None
    state_payload = None
    if artifacts is not None:
        summary_path = Path(artifacts.summary_path)
        if summary_path.exists():
            summary_payload = json.loads(summary_path.read_text(encoding="utf-8"))
        state_path = Path(artifacts.state_path)
        if state_path.exists():
            state_payload = json.loads(state_path.read_text(encoding="utf-8"))

    if summary_payload is not None:
        solved = bool(summary_payload.get("solved"))

    token_usage = _token_usage(
        (summary_payload or {}).get("token_usage") if summary_payload is not None else None
    )
    metadata = challenge_metadata(challenge)
    log_payload = {
        "args": _sanitize_for_log(vars(args)),
        "challenge": challenge.challenge_info,
        "challenge_metadata": metadata,
        "objective": objective,
        "authorized_scope": authorized_scope,
        "effective_max_cycles": effective_max_cycles,
        "success": solved, "solved": solved,
        "status": "solved" if solved else ("interrupted" if interrupted else "completed"),
        "artifacts": None if artifacts is None else artifacts.model_dump(mode="json"),
        "summary": summary_payload,
        "token_usage": token_usage,
        "state": state_payload,
        "error": error_payload,
        "llm_error": is_llm_error,
        "traceback": traceback_text,
        "start_time": started_at, "end_time": ended_at,
        "runtime_sec": round(ended_at - started_at, 3),
    }
    write_log(logfile, log_payload)

    return {
        "challenge": challenge.canonical_name,
        "solved": solved,
        "status": log_payload["status"],
        "logfile": str(logfile),
        "runtime_sec": round(ended_at - started_at, 3),
        "token_usage": token_usage,
        "error": error_payload,
        "api_error": is_api_error,
        "llm_error": is_llm_error,
        "interrupted": interrupted,
    }


# ---------------------------------------------------------------------------
# Batch execution
# ---------------------------------------------------------------------------

def run_all_challenges(args: argparse.Namespace) -> int:
    """Run every challenge in the split. Returns exit code."""
    from killchain_docker.batch.dataset import load_dataset, challenge_names_for_category
    from killchain_docker.batch.dataset import normalize_category

    dataset = load_dataset(args)
    category_filter = normalize_category(getattr(args, "category", None))
    all_names = challenge_names_for_category(dataset, category_filter)

    total = len(all_names)
    if total == 0:
        print("No challenges found in the specified split/category.")
        return 1

    print(f"\n{'='*72}")
    print(f"  Batch run: {total} challenges in split='{args.split}'")
    print(f"{'='*72}\n")

    results: list[dict[str, Any]] = []
    solved_count = 0
    failed_count = 0
    batch_start = time.time()

    try:
        for idx, name in enumerate(all_names, 1):
            print(f"\n{'─'*72}")
            print(f"  [{idx}/{total}] {name}")
            print(f"{'─'*72}")

            try:
                args.challenge = name
                challenge = CTFChallenge(dataset.get(name), dataset.basedir)
            except Exception as exc:
                print(f"  [error] Failed to load challenge {name}: {exc}")
                results.append({
                    "challenge": name, "solved": False, "status": "load_error",
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                    "api_error": False, "llm_error": False,
                })
                failed_count += 1
                continue

            result = run_single_challenge(args, challenge)
            results.append(result)
            if result.get("solved"):
                solved_count += 1
            elif result.get("status") != "skipped":
                failed_count += 1

            if result.get("api_error"):
                print(f"  LLM/API error detected — aborting batch run.")
                break
            if result.get("status") == "interrupted":
                break
    except (KeyboardInterrupt, SystemExit):
        print(f"\n  Batch interrupted — saving progress.")

    batch_end = time.time()
    print(f"\n{'='*72}")
    print(f"  Batch complete: {len(results)}/{total} attempted")
    print(f"    Solved: {solved_count}  Failed: {failed_count}")
    print(f"    Total time: {batch_end - batch_start:.1f}s")
    print(f"{'='*72}\n")

    return 0 if solved_count > 0 or failed_count == 0 else 1
