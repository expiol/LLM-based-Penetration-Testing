from __future__ import annotations

import argparse
import concurrent.futures
from contextlib import contextmanager
import getpass
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None

from nyuctf.challenge import CTFChallenge
from nyuctf.dataset import CTFDataset

from killchain_docker.controller import RunConfig, run_assessment
from killchain_docker.environment import CTFEnvironment
from killchain_docker.llm import LLMClientError, build_llm_client_from_env
from killchain_docker.tools import build_execution_plane
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                    运行参数配置                        ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

CHALLENGE       = "__all__"     # 挑战名称；设为 "__random__" 从 SPLIT 分片中随机选一个；设为 "__all__" 跑完整个 SPLIT
DATASET         = None                      # 数据集 JSON 路径；使用默认 NYUCTF 数据集时留 None
SPLIT           = "development"                    # 数据集分片: "test" 或 "development"
CATEGORY        = None                 # 题目类型过滤，如 "web" / "pwn" / "rev"；留 None 表示不筛选
CONTAINER_IMAGE = "ctfenv:latest"  # Docker 镜像（与 setup.sh / Dockerfile 构建的 tag 一致）
CONTAINER_NETWORK = "ctfnet"                # Docker 网络
OBJECTIVE       = None                      # 覆盖默认目标（留 None 自动推导）
SCOPE           = None                      # 授权范围列表，如 ["http://target:8080"]；留 None 自动推导
MAX_CYCLES      = 25                        
QUIET           = False                     # 静默模式（不输出编排事件流）
DEBUG           = True                      # 调试模式（失败时打印详细上下文）
SKIP_EXIST      = False                     # 跳过已存在的日志
LOGDIR          = None                      # 日志目录；留 None 使用默认路径 logs/<user>
NAME            = "5.15_development_2"                      # 实验名称（在日志目录下创建子目录）
INDEX           = None                      # 实验轮次（在日志目录下创建子目录）
OUTPUT_ROOT     = None                      # 运行产物目录；留 None 使用默认路径
PARALLEL_WORKERS = 1                       # 并发 worker 数（run-all 或 replicas）
REPLICAS        = 1                        # 单挑战重复运行次数（>1 时并发隔离运行；先压成 1，确认效果稳定再加）

# ══════════════════════════════════════════════════════════════════════════════

SENSITIVE_KEYS = frozenset({"api_key", "authorization", "token", "secret", "password"})
PORT_CONFLICT_RE = re.compile(r"listen tcp [^:]+:(?P<port>\d+): bind: address already in use")
TOKEN_USAGE_KEYS = ("llm_calls", "prompt_tokens", "completion_tokens", "total_tokens")
SCRIPT_DIR = Path(__file__).parent.resolve()
DEFAULT_LOGDIR = SCRIPT_DIR / "logs" / getpass.getuser()
LLM_GATEWAY_CONFIG = SCRIPT_DIR / "configs" / "llm_gateway.json"
COMPOSE_CHALLENGE_LOCK = Path(tempfile.gettempdir()) / "killchain_docker_compose_challenges.lock"
LEGACY_LLM_ENV_KEYS = (
    "AUTOPENTEST_LLM_MODE",
    "AUTOPENTEST_LLM_CONFIG_PATH",
    "AUTOPENTEST_LLM_PROVIDER",
    "AUTOPENTEST_LLM_BASE_URL",
    "AUTOPENTEST_LLM_MODEL",
    "AUTOPENTEST_LLM_API_KEY",
    "AUTOPENTEST_LLM_SCHEMA_MODELS",
    "AUTOPENTEST_LLM_TIMEOUT_S",
    "AUTOPENTEST_LLM_MAX_RETRIES",
    "AUTOPENTEST_LLM_MAX_COMPLETION_TOKENS",
)


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
    combined = "\n".join(part for part in (err_out, std_out) if part)
    extras: list[str] = []
    match = PORT_CONFLICT_RE.search(combined)
    if match is not None:
        extras.append(
            f"Host port {match.group('port')} is already in use. Stop the conflicting process or free that port before rerunning."
        )
    if "does not match the detected host platform" in combined:
        extras.append(
            "Docker is emulating a different image architecture than the host. Startup may be slower on Apple Silicon."
        )
    if err_out:
        payload = f"{message}\nstderr:\n{err_out}"
        if extras:
            payload += "\n" + "\n".join(extras)
        return payload
    if std_out:
        payload = f"{message}\nstdout:\n{std_out}"
        if extras:
            payload += "\n" + "\n".join(extras)
        return payload
    if extras:
        return f"{message}\n" + "\n".join(extras)
    return message


_CONTAINER_CONFLICT_RE = re.compile(
    r"(address already in use"
    r"|is already in use by container"
    r"|Conflict\. The container name"
    r"|endpoint with name [^ ]+ already exists)",
    re.IGNORECASE,
)


def _challenge_compose_path(challenge: CTFChallenge) -> Path | None:
    candidate = getattr(challenge, "challenge_dir", None)
    if candidate is None:
        return None
    compose = Path(candidate) / "docker-compose.yml"
    return compose if compose.exists() else None


def _uses_compose(challenge: CTFChallenge) -> bool:
    return bool(getattr(challenge, "container", False) and _challenge_compose_path(challenge))


@contextmanager
def _compose_challenge_run_lock(challenge: CTFChallenge):
    """Serialize compose-backed challenges across process workers.

    NYUCTF compose files reuse fixed host ports and shared network aliases
    (for example ``web.chal.csaw.io``), so multiple service challenges cannot
    safely share the same Docker network at the same time.
    """
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


def _docker_compose_down(challenge: CTFChallenge) -> None:
    """Best-effort cleanup so the next ``up`` doesn't hit name/port conflicts."""
    compose = _challenge_compose_path(challenge)
    if compose is None:
        return
    try:
        subprocess.run(
            [
                "docker", "compose", "-f", str(compose),
                "down", "--volumes", "--remove-orphans",
            ],
            check=False,
            capture_output=True,
            timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        # Cleanup is opportunistic — if Docker itself is broken the retry call
        # downstream will surface the real error.
        return


def _start_challenge_with_retry(
    challenge: CTFChallenge,
    *,
    attempts: int = 3,
    debug: bool = False,
) -> None:
    """Start the challenge container, retrying past port/registry hiccups.

    1. On port/container/endpoint conflict: run ``docker compose down`` and try again.
    2. On other CalledProcessError: sleep 5s and retry — common case is a flaky
       registry pull (``context deadline exceeded``).
    3. After ``attempts`` total tries, raise the final CalledProcessError.
    """
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
                f"{'port/container conflict' if conflict else 'transient error'}; "
                f"retrying..."
            )
            if debug and combined:
                print(combined[-600:])
            if conflict:
                _docker_compose_down(challenge)
            else:
                time.sleep(5)
    assert last_exc is not None
    raise last_exc


def _mask_secret(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-4:]}"


def _sanitize_for_log(value: Any, *, key: str | None = None) -> Any:
    lowered_key = (key or "").lower()
    if lowered_key in SENSITIVE_KEYS:
        return _mask_secret(value)
    if isinstance(value, dict):
        return {item_key: _sanitize_for_log(item_value, key=item_key) for item_key, item_value in value.items()}
    if isinstance(value, list):
        return [_sanitize_for_log(item, key=key) for item in value]
    return value


def _args_from_config() -> argparse.Namespace:
    """Build an argparse.Namespace from the file-level config variables."""
    return argparse.Namespace(
        challenge=CHALLENGE,
        run_all=CHALLENGE == "__all__",
        category=CATEGORY,
        dataset=DATASET,
        split=SPLIT,
        container_image=CONTAINER_IMAGE,
        container_network=CONTAINER_NETWORK,
        objective=OBJECTIVE,
        scope=SCOPE,
        max_cycles=MAX_CYCLES,
        quiet=QUIET,
        debug=DEBUG,
        skip_exist=SKIP_EXIST,
        logdir=LOGDIR or str(DEFAULT_LOGDIR),
        name=NAME,
        index=INDEX,
        output_root=OUTPUT_ROOT,
        parallel_workers=PARALLEL_WORKERS,
        replicas=REPLICAS,
    )


def _normalize_category(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = str(value).strip().lower()
    return normalized or None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the structured LLM killchain on NYUCTF challenges",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--challenge", default=None, help="Name of the challenge (omit when using --run-all)")
    parser.add_argument(
        "--run-all",
        action="store_true",
        help="Run ALL challenges in the specified split (test or development) sequentially",
    )
    parser.add_argument(
        "--category",
        help="Optional category filter (e.g. web, pwn, rev, crypto); applies to --run-all and --challenge __random__",
    )
    parser.add_argument(
        "--dataset",
        help="Dataset JSON path. Only provide if not using the NYUCTF dataset at default path",
    )
    parser.add_argument(
        "-s",
        "--split",
        default="development",
        choices=["test", "development"],
        help="Dataset split to select. Only used when --dataset is not provided.",
    )
    parser.add_argument(
        "-C",
        "--container-image",
        default="ctfenv:latest",
        help="Docker image for the CTF solver environment (see setup.sh)",
    )
    parser.add_argument(
        "-N",
        "--container-network",
        default="ctfnet",
        help="The Docker network to use for the NYU agent environment",
    )
    parser.add_argument(
        "--objective",
        help="Override the derived objective passed into the killchain workflow",
    )
    parser.add_argument(
        "--scope",
        action="append",
        dest="scope",
        help="Override an authorized scope entry; may be passed multiple times",
    )
    parser.add_argument("--max-cycles", type=int, default=8, help="Maximum orchestrator cycles")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress orchestrator event streaming")
    parser.add_argument("-d", "--debug", action="store_true", help="Print additional debug context on failures")
    parser.add_argument(
        "--skip-exist",
        "--skip-existing",
        dest="skip_exist",
        action="store_true",
        help="Skip the run if the per-challenge log already exists",
    )
    parser.add_argument(
        "-L",
        "--logdir",
        default=str(DEFAULT_LOGDIR),
        help="Log directory to write the run log",
    )
    parser.add_argument("-n", "--name", help="Experiment name (creates subdir in logdir)")
    parser.add_argument("-i", "--index", help="Round index of the experiment (creates subdir in logdir)")
    parser.add_argument(
        "--output-root",
        help="Directory where run artifacts are stored. Defaults to a challenge-specific subdir under logdir.",
    )
    parser.add_argument(
        "--parallel-workers",
        type=int,
        default=1,
        help="Number of isolated process workers for --run-all and --replicas",
    )
    parser.add_argument(
        "--replicas",
        type=int,
        default=1,
        help="Run the same single challenge N isolated replicas in parallel",
    )
    return parser


def load_challenge(args: argparse.Namespace) -> CTFChallenge:
    dataset = _load_dataset(args)
    category_filter = _normalize_category(getattr(args, "category", None))

    if args.challenge == "__random__":
        names = _challenge_names_for_category(dataset, category_filter)
        if not names:
            message = f"No challenges found in split '{args.split}'"
            if category_filter:
                message += f" with category '{category_filter}'"
            raise ValueError(message)
        chosen = random.choice(names)
        if category_filter:
            print(f"Randomly selected challenge from category '{category_filter}': {chosen}")
        else:
            print(f"Randomly selected challenge: {chosen}")
        args.challenge = chosen

    challenge_info = dataset.get(args.challenge)
    challenge_category = _normalize_category(challenge_info.get("category"))
    if category_filter and challenge_category != category_filter:
        raise ValueError(
            f"Challenge '{args.challenge}' has category '{challenge_info.get('category')}', "
            f"which does not match category filter '{category_filter}'."
        )

    return CTFChallenge(challenge_info, dataset.basedir)


def resolve_experiment_logdir(args: argparse.Namespace) -> Path:
    logdir = Path(args.logdir).expanduser().resolve()
    suffix = "_".join(
        part for part in (
            getattr(args, "name", None),
            f"round{args.index}" if getattr(args, "index", None) else None,
        )
        if part
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


def _challenge_port(challenge: CTFChallenge) -> int | None:
    """Return the challenge's exposed port.

    ``CTFChallenge.port`` reads ``internal_port``, but many challenge.json
    files only have ``port``.  Try both.
    """
    return challenge.port or challenge.challenge.get("port") or None


def derive_authorized_scope(challenge: CTFChallenge) -> list[str]:
    if not challenge.server_name:
        return []

    port = _challenge_port(challenge)
    category = (challenge.category or "").strip().lower()
    is_web = challenge.server_type == "web" or category == "web"

    if is_web and port:
        proto = str(challenge.challenge.get("proto") or "http").strip().lower() or "http"
        if proto not in {"http", "https"}:
            proto = "http"
        return [f"{proto}://{challenge.server_name}:{port}"]

    if port:
        return [f"tcp://{challenge.server_name}:{port}"]

    if challenge.files and challenge.server_type is None:
        return []

    return [challenge.server_name]


def estimate_max_cycles(challenge: CTFChallenge, authorized_scope: list[str], base_cycles: int = 8) -> int:
    """Estimate the cycle budget from challenge structure."""
    cycles = base_cycles
    num_files = len(challenge.files) if challenge.files else 0
    has_server = bool(challenge.server_name and _challenge_port(challenge))

    if num_files > 0:
        cycles += 3
    if has_server:
        cycles += 3
    if has_server and num_files > 0:
        cycles += 2

    return min(cycles, 30)


def derive_objective(challenge: CTFChallenge, authorized_scope: list[str]) -> str:
    from killchain_docker.prompts import get_prompts

    category = str(challenge.category or "").lower()
    lines = [
        (
            f"Solve the NYU CTF challenge '{challenge.name}' in the authorized docker environment. "
            f"Category: {challenge.category}."
        ),
        f"Challenge description: {challenge.description}",
    ]
    if authorized_scope:
        lines.append("Authorized scope: " + ", ".join(authorized_scope))
    if challenge.files:
        lines.append(
            "Challenge files are available inside the agent container under /home/ctfplayer/ctf_files."
        )

    prompts = get_prompts(category)
    parts = [prompts.objective_hint]
    if challenge.files and not authorized_scope:
        parts.append(
            "Challenge files are available inside the agent container under "
            "/home/ctfplayer/ctf_files. Inspect them first and derive concrete "
            "flag candidates from the local artifacts."
        )
    lines.append(" ".join(parts))
    return "\n".join(lines)


def configure_llm_environment() -> None:
    """Clear legacy LLM env overrides; the gateway reads configs/llm_gateway.json."""
    for key in LEGACY_LLM_ENV_KEYS:
        os.environ.pop(key, None)


_PROVIDED_FLAG_FORMAT_RE = re.compile(r"^[A-Za-z0-9_]+\{")


def _resolve_flag_format(challenge: CTFChallenge) -> str:
    """Return a usable ``flag_format`` even when the dataset says 'not provided'.

    Three cases:

    1. Dataset advertises a concrete ``prefix{...}`` shape — pass through.
    2. Dataset is missing/placeholder but ``challenge.flag`` is a real
       ``prefix{body}`` token — derive ``prefix{...}``.
    3. Dataset is missing/placeholder AND the actual flag is a bare token
       (NYU has a handful of these, e.g. CSAW 2013 stfu's
       ``STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME``) — return ``""``.  The
       solver_execution plugin and SolverResultParser interpret an empty
       ``flag_format`` as "harvest single-token candidates from stdout".
    4. Truly unknown — default to NYU's canonical ``flag{...}``.

    Returning ``"not provided"`` is never useful because the LLM has been
    observed to take that literally as the flag format.
    """
    raw = (challenge.flag_format or "").strip()
    if raw and _PROVIDED_FLAG_FORMAT_RE.match(raw):
        return raw

    actual_flag = (getattr(challenge, "flag", None) or "").strip()
    if actual_flag:
        if _PROVIDED_FLAG_FORMAT_RE.match(actual_flag):
            prefix = actual_flag.split("{", 1)[0]
            return f"{prefix}{{...}}"
        # Bare-token flag — empty string signals bare-token harvest.
        return ""

    return "flag{...}"


def challenge_metadata(challenge: CTFChallenge) -> dict[str, Any]:
    return {
        "canonical_name": challenge.canonical_name,
        "name": challenge.name,
        "category": challenge.category,
        "flag_format": _resolve_flag_format(challenge),
        "files": list(challenge.files),
        "server_name": challenge.server_name,
        "port": challenge.port,
        "server_type": challenge.server_type,
        "server_description": challenge.server_description,
    }


def artifact_contains_flag(artifact_paths: list[str], flag: str) -> bool:
    for raw_path in artifact_paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        try:
            if flag in path.read_text(encoding="utf-8", errors="ignore"):
                return True
        except OSError:
            continue
    return False


def write_log(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _safe_read_json(path: str | Path | None) -> dict[str, Any] | None:
    if not path:
        return None
    try:
        candidate = Path(path)
        if not candidate.exists():
            return None
        payload = json.loads(candidate.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:
        return None


def _utc_timestamp(ts: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def _token_usage(value: Any) -> dict[str, int]:
    payload = value if isinstance(value, dict) else {}
    return {key: int(payload.get(key) or 0) for key in TOKEN_USAGE_KEYS}


def _avg_token_usage(usages: list[dict[str, int]]) -> dict[str, float]:
    if not usages:
        return {key: 0.0 for key in TOKEN_USAGE_KEYS}
    return {
        key: round(sum(int(item.get(key) or 0) for item in usages) / len(usages), 3)
        for key in TOKEN_USAGE_KEYS
    }


def _sum_numeric_dicts(items: list[dict[str, int]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for item in items:
        for key, value in item.items():
            totals[key] = totals.get(key, 0) + int(value or 0)
    return totals


def _load_llm_experiment_config() -> dict[str, Any]:
    """Return sanitized gateway settings useful for experiment reporting."""

    payload = _safe_read_json(LLM_GATEWAY_CONFIG) or {}
    if not payload:
        return {"config_path": str(LLM_GATEWAY_CONFIG), "available": False}
    sanitized = _sanitize_for_log(payload)
    sanitized["config_path"] = str(LLM_GATEWAY_CONFIG)
    sanitized["available"] = True
    return sanitized


def _state_metrics(state_payload: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(state_payload, dict):
        return {}

    todos = list(state_payload.get("todos") or [])
    todo_status_counts: dict[str, int] = {}
    worker_counts: dict[str, int] = {}
    for todo in todos:
        if not isinstance(todo, dict):
            continue
        status = str(todo.get("status") or "unknown")
        worker_name = str(todo.get("assigned_worker") or "unassigned")
        todo_status_counts[status] = todo_status_counts.get(status, 0) + 1
        worker_counts[worker_name] = worker_counts.get(worker_name, 0) + 1

    evidence = state_payload.get("evidence") or {}
    evidence_tool_counts: dict[str, int] = {}
    if isinstance(evidence, dict):
        for record in evidence.values():
            if not isinstance(record, dict):
                continue
            tool_name = str(record.get("tool_name") or "unknown")
            evidence_tool_counts[tool_name] = evidence_tool_counts.get(tool_name, 0) + 1

    return {
        "run_id": state_payload.get("run_id"),
        "run_status": state_payload.get("status"),
        "stop_reason": state_payload.get("stop_reason"),
        "todo_count": len(todos),
        "todo_status_counts": todo_status_counts,
        "worker_counts": worker_counts,
        "open_todo_count": sum(
            todo_status_counts.get(status, 0)
            for status in ("pending", "running")
        ),
        "partial_todo_count": todo_status_counts.get("partial", 0),
        "interrupted_todo_count": todo_status_counts.get("interrupted", 0),
        "round_count": len(state_payload.get("rounds") or []),
        "evidence_count": len(evidence) if isinstance(evidence, dict) else 0,
        "evidence_tool_counts": evidence_tool_counts,
        "asset_count": len(state_payload.get("assets") or {}),
        "finding_count": len(state_payload.get("findings") or {}),
        "credential_count": len(state_payload.get("credentials") or {}),
        "execution_count": len(state_payload.get("execution_log") or []),
    }


def _failure_buckets(log_payload: dict[str, Any], result: dict[str, Any]) -> list[str]:
    """Classify common failure modes for experiment summaries."""

    buckets: set[str] = set()
    if result.get("solved"):
        return []

    haystack_parts: list[str] = []
    for source in (result, log_payload):
        for key in ("status", "finish_reason", "traceback"):
            value = source.get(key) if isinstance(source, dict) else None
            if value:
                haystack_parts.append(str(value))
        error = source.get("error") if isinstance(source, dict) else None
        if isinstance(error, dict):
            haystack_parts.extend(str(value) for value in error.values() if value)
        elif error:
            haystack_parts.append(str(error))

    state_payload = log_payload.get("state") if isinstance(log_payload, dict) else None
    if isinstance(state_payload, dict):
        haystack_parts.extend(str(note) for note in state_payload.get("orchestration_notes") or [])
        for todo in state_payload.get("todos") or []:
            if not isinstance(todo, dict):
                continue
            haystack_parts.extend(
                str(todo.get(key) or "")
                for key in ("goal", "result_summary", "error")
            )
        for record in (state_payload.get("evidence") or {}).values():
            if not isinstance(record, dict):
                continue
            haystack_parts.append(str(record.get("summary") or ""))
        for record in state_payload.get("execution_log") or []:
            if not isinstance(record, dict):
                continue
            haystack_parts.extend(
                str(record.get(key) or "")
                for key in ("summary", "error")
            )

    haystack = "\n".join(haystack_parts).lower()

    if (
        "missing required metadata.script_code" in haystack
        or "no script code provided" in haystack
        or "script execution skipped" in haystack
    ):
        buckets.add("script_missing_code")
    if "script execution failed (exit" in haystack:
        buckets.add("script_nonzero_exit")
    if (
        "missing required metadata.source_files" in haystack
        or "missing required metadata.pcap_files" in haystack
        or "missing required metadata.binary_files" in haystack
        or "missing required metadata.archive_files" in haystack
        or "missing required metadata.database_files" in haystack
        or "missing required metadata.repo_paths" in haystack
        or "no requested source files could be read" in haystack
        or "no requested pcap files could be read" in haystack
        or "no requested binary files could be read" in haystack
        or "completed for 0 file(s)" in haystack
        or "completed for 0 binary(ies)" in haystack
    ):
        buckets.add("tool_missing_target_files")
    if (
        "no requested source files could be read" in haystack
        or "missing required metadata.source_files" in haystack
        or "source review failed" in haystack
    ):
        buckets.add("source_target_unresolved")
    if "candidate mismatch" in haystack:
        buckets.add("candidate_mismatch")
    if "rejected flag candidate" in haystack or "escaped_byte_candidate" in haystack:
        buckets.add("candidate_rejected")
    if "family" in haystack and "cooldown" in haystack:
        buckets.add("stagnated")
    if "max_cycles_exhausted" in haystack:
        buckets.add("max_cycles_exhausted")
    if result.get("llm_error") or log_payload.get("llm_error") or "llm_error" in haystack:
        buckets.add("llm_error")
    if (
        "docker compose" in haystack
        or "ports are not available" in haystack
        or "bind: address already in use" in haystack
        or "port is already allocated" in haystack
        or "start_challenge_container" in haystack
    ):
        buckets.add("docker_start_error")
    status_values = {
        str(value)
        for value in (
            result.get("status"),
            result.get("finish_reason"),
            log_payload.get("status"),
            log_payload.get("finish_reason"),
        )
        if value
    }
    if "interrupted" in status_values or "keyboardinterrupt" in haystack:
        buckets.add("interrupted")
    state_metrics = result.get("state_metrics")
    if not isinstance(state_metrics, dict) or not state_metrics:
        state_metrics = log_payload.get("state_metrics")
    if not isinstance(state_metrics, dict) or not state_metrics:
        state_payload = log_payload.get("state")
        state_metrics = _state_metrics(state_payload if isinstance(state_payload, dict) else None)
    if isinstance(state_metrics, dict) and int(state_metrics.get("partial_todo_count") or 0) > 0:
        buckets.add("partial_no_candidate")
    if "partial_no_candidate" in haystack or "partial: no flag candidate" in haystack:
        buckets.add("partial_no_candidate")
    if _is_unsolved_exhausted(log_payload, result):
        buckets.add("unsolved_exhausted")

    return sorted(buckets)


def _is_unsolved_exhausted(log_payload: dict[str, Any], result: dict[str, Any]) -> bool:
    if result.get("solved") or log_payload.get("solved"):
        return False
    status_values = {
        str(value)
        for value in (
            result.get("status"),
            result.get("finish_reason"),
            log_payload.get("status"),
            log_payload.get("finish_reason"),
        )
        if value
    }
    if "unsolved_exhausted" in status_values:
        return True
    if "completed" not in status_values:
        return False
    metrics = result.get("state_metrics")
    if not isinstance(metrics, dict) or not metrics:
        metrics = log_payload.get("state_metrics")
    if not isinstance(metrics, dict) or not metrics:
        state_payload = log_payload.get("state")
        metrics = _state_metrics(state_payload if isinstance(state_payload, dict) else None)
    if metrics.get("open_todo_count") != 0:
        return False
    todo_counts = metrics.get("todo_status_counts") or {}
    return bool(todo_counts.get("completed") or metrics.get("todo_count"))


API_BALANCE_PATTERNS = [
    "insufficient_quota",
    "insufficient balance",
    "Arrearage",
    "billing",
    "exceeded your current quota",
    "account has been suspended",
    "rate_limit_exceeded",
    "You exceeded your current quota",
    "余额不足",
    "欠费",
    "账户余额",
]


def _is_api_balance_error(exc: Exception) -> bool:
    """Detect API balance/quota exhaustion from exception message or type."""
    exc_str = str(exc).lower()
    exc_type = type(exc).__name__
    if "RateLimit" in exc_type or "AuthenticationError" in exc_type:
        return True
    for pattern in API_BALANCE_PATTERNS:
        if pattern.lower() in exc_str:
            return True
    return False


def run_single_challenge(
    args: argparse.Namespace,
    challenge: CTFChallenge,
) -> dict[str, Any]:
    """Run a single challenge and return the result dict. Always saves log to disk."""
    logfile = resolve_logfile(args, challenge)

    if logfile.exists() and args.skip_exist:
        print(f"  [skip] {challenge.canonical_name} — log exists: {logfile}")
        return {
            "challenge": challenge.canonical_name,
            "status": "skipped",
            "solved": False,
            "api_error": False,
            "llm_error": False,
        }

    with _compose_challenge_run_lock(challenge):
        return _run_single_challenge_inner(args, challenge, logfile)


def _run_single_challenge_inner(
    args: argparse.Namespace,
    challenge: CTFChallenge,
    logfile: Path,
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
        metadata={
            "challenge": challenge_metadata(challenge),
        },
    )

    environment = CTFEnvironment(challenge, args.container_image, args.container_network)
    started_at = time.time()
    artifacts = None
    llm_client = None
    error_payload = None
    traceback_text = None
    solved = False
    is_api_error = False
    is_llm_error = False
    interrupted = False

    try:
        configure_llm_environment()
        llm_client = build_llm_client_from_env(preflight=True)
        _start_challenge_with_retry(challenge, debug=args.debug)
        environment.setup()
        if not environment.container:
            raise RuntimeError("environment container did not start")

        execution_plane = build_execution_plane(
            argv_prefix=["docker", "exec", environment.container],
            python_executable="python3",
        )
        artifacts = run_assessment(
            config,
            execution_plane=execution_plane,
            expected_flag=challenge.flag,
            llm_client=llm_client,
        )
    except (KeyboardInterrupt, SystemExit) as exc:
        interrupted = True
        code = getattr(exc, "code", None)
        message = f"Run interrupted by {type(exc).__name__}"
        if code not in (None, ""):
            message += f" (code={code})"
        error_payload = {
            "type": type(exc).__name__,
            "message": message,
        }
        try:
            traceback_text = traceback.format_exc()
        except Exception:
            traceback_text = message
        if args.debug:
            print(traceback_text)
    except Exception as exc:
        message = (
            _called_process_message(exc)
            if isinstance(exc, subprocess.CalledProcessError)
            else str(exc)
        )
        error_payload = {
            "type": type(exc).__name__,
            "message": message,
        }
        # CPython 3.12 traceback.format_exc occasionally raises StopIteration
        # on deeply-nested exception chains (instructor + tenacity + openai).
        # Fall back to a short repr so the batch loop never gets killed by
        # its own error reporter.
        try:
            traceback_text = traceback.format_exc()
        except Exception:
            traceback_text = f"{type(exc).__name__}: {exc}"
        is_llm_error = isinstance(exc, LLMClientError)
        is_api_error = is_llm_error or _is_api_balance_error(exc)
        if args.debug:
            print(traceback_text)
    finally:
        teardown_error: Exception | None = None
        try:
            environment.teardown()
        except Exception as exc:
            teardown_error = exc
            if args.debug:
                print(traceback.format_exc())
        try:
            challenge.stop_challenge_container()
        except Exception as exc:
            if teardown_error is None:
                teardown_error = exc
            if args.debug:
                print(traceback.format_exc())
        if teardown_error is not None and error_payload is None:
            tm = (
                _called_process_message(teardown_error)
                if isinstance(teardown_error, subprocess.CalledProcessError)
                else str(teardown_error)
            )
            error_payload = {
                "type": type(teardown_error).__name__,
                "message": tm,
            }

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
    elif artifacts is not None:
        solved = artifact_contains_flag(
            [
                artifacts.state_path,
                artifacts.summary_path,
                artifacts.report_path,
                artifacts.events_path,
                artifacts.evidence_path,
            ],
            challenge.flag,
        )

    state_metrics = _state_metrics(state_payload)
    artifact_status = artifacts.status if artifacts is not None else "failed"
    if interrupted:
        artifact_status = "interrupted"
    interrupted = interrupted or artifact_status == "interrupted"
    unsolved_exhausted = (
        not solved
        and artifact_status == "completed"
        and state_metrics.get("open_todo_count") == 0
        and bool(state_metrics.get("todo_count"))
    )
    finish_reason = "solved" if solved else (
        "interrupted" if interrupted else (
            "unsolved_exhausted" if unsolved_exhausted else artifact_status
        )
    )
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
        "success": solved,
        "solved": solved,
        "status": finish_reason,
        "finish_reason": finish_reason,
        "interrupted": interrupted,
        "artifacts": None if artifacts is None else artifacts.model_dump(mode="json"),
        "summary": summary_payload,
        "token_usage": token_usage,
        "state_metrics": state_metrics,
        "state": state_payload,
        "error": error_payload,
        "llm_error": is_llm_error,
        "traceback": traceback_text,
        "start_time": started_at,
        "end_time": ended_at,
        "runtime_sec": round(ended_at - started_at, 3),
    }
    write_log(logfile, log_payload)

    return {
        "challenge": challenge.canonical_name,
        "solved": solved,
        "status": finish_reason,
        "logfile": str(logfile),
        "runtime_sec": round(ended_at - started_at, 3),
        "run_id": None if artifacts is None else artifacts.run_id,
        "artifacts": None if artifacts is None else artifacts.model_dump(mode="json"),
        "challenge_metadata": metadata,
        "authorized_scope": authorized_scope,
        "max_cycles": effective_max_cycles,
        "token_usage": token_usage,
        "state_metrics": state_metrics,
        "error": error_payload,
        "api_error": is_api_error,
        "llm_error": is_llm_error,
        "interrupted": interrupted,
    }


def _load_dataset(args: argparse.Namespace) -> CTFDataset:
    if args.dataset is not None:
        return CTFDataset(dataset_json=args.dataset)
    return CTFDataset(split=args.split)


def _challenge_names_for_category(dataset: CTFDataset, category: str | None) -> list[str]:
    category_filter = _normalize_category(category)
    all_names = sorted(dict(dataset.all()).keys())
    if not category_filter:
        return all_names

    filtered: list[str] = []
    for name in all_names:
        try:
            challenge_info = dataset.get(name)
        except Exception:
            continue
        if _normalize_category(challenge_info.get("category")) == category_filter:
            filtered.append(name)
    return filtered


def run_all_challenges(args: argparse.Namespace) -> int:
    """Run every challenge in the split, optionally with isolated parallel workers."""
    dataset = _load_dataset(args)
    category_filter = _normalize_category(getattr(args, "category", None))
    all_names = _challenge_names_for_category(dataset, category_filter)

    if category_filter:
        print(f"Filtered to {len(all_names)} challenges with category='{category_filter}'")

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
    skipped_count = 0
    batch_start = time.time()
    batch_interrupted = False
    current_name: str | None = None

    workers = max(1, int(getattr(args, "parallel_workers", 1) or 1))
    try:
        if workers == 1:
            for idx, name in enumerate(all_names, 1):
                current_name = name
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
                        "api_error": False,
                        "llm_error": False,
                    })
                    failed_count += 1
                    continue

                result = run_single_challenge(args, challenge)
                results.append(result)
                solved_count, failed_count, skipped_count = _update_result_counters(
                    result, solved_count, failed_count, skipped_count
                )
                _save_batch_progress(args, results, batch_start)

                if result.get("api_error"):
                    print(f"\n{'!'*72}")
                    print(f"  LLM/API error detected — aborting batch run.")
                    print(f"  Completed {idx}/{total} challenges before abort.")
                    print(f"{'!'*72}")
                    break
                if result.get("status") == "interrupted":
                    print(f"\n{'!'*72}")
                    print("  Run interrupted — stopping batch run after saving progress.")
                    print(f"  Completed {idx}/{total} challenges before interrupt.")
                    print(f"{'!'*72}")
                    break
        else:
            print(f"  Parallel mode enabled: {workers} isolated workers")
            print("  Compose-backed service challenges are serialized to avoid Docker port/alias conflicts.")
            base_args = vars(args).copy()
            with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
                future_map = {
                    executor.submit(_run_named_challenge_worker, base_args, name): name
                    for name in all_names
                }
                try:
                    for idx, future in enumerate(concurrent.futures.as_completed(future_map), 1):
                        name = future_map[future]
                        current_name = name
                        print(f"\n{'─'*72}")
                        print(f"  [{idx}/{total}] {name}")
                        print(f"{'─'*72}")
                        try:
                            result = future.result()
                        except Exception as exc:
                            result = {
                                "challenge": name,
                                "solved": False,
                                "status": "worker_error",
                                "error": {"type": type(exc).__name__, "message": str(exc)},
                                "api_error": isinstance(exc, LLMClientError),
                                "llm_error": isinstance(exc, LLMClientError),
                            }
                        results.append(result)
                        solved_count, failed_count, skipped_count = _update_result_counters(
                            result, solved_count, failed_count, skipped_count
                        )
                        err = result.get("error")
                        if result.get("status") == "skipped":
                            print(f"  [SKIPPED] {name}")
                        elif result.get("solved"):
                            print(f"  [SOLVED] {name}")
                        elif err:
                            print(f"  [FAILED] {name}: {err.get('type', '?')}: {err.get('message', '')[:120]}")
                        else:
                            print(f"  [FAILED] {name}: status={result.get('status')}")
                        _save_batch_progress(args, results, batch_start)
                        if result.get("status") == "interrupted":
                            for pending in future_map:
                                pending.cancel()
                            print("  Run interrupted — stopping parallel batch after saving progress.")
                            break
                        if result.get("api_error"):
                            for pending in future_map:
                                pending.cancel()
                            print("  LLM/API error detected — stopping parallel batch after saving progress.")
                            break
                except (KeyboardInterrupt, SystemExit):
                    for pending in future_map:
                        pending.cancel()
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
    except (KeyboardInterrupt, SystemExit) as exc:
        batch_interrupted = True
        code = getattr(exc, "code", None)
        message = f"Batch interrupted by {type(exc).__name__}"
        if code not in (None, ""):
            message += f" (code={code})"
        if current_name and all(r.get("challenge") != current_name for r in results):
            interrupted_result = {
                "challenge": current_name,
                "solved": False,
                "status": "interrupted",
                "error": {"type": type(exc).__name__, "message": message},
                "api_error": False,
                "llm_error": False,
                "interrupted": True,
            }
            results.append(interrupted_result)
            solved_count, failed_count, skipped_count = _update_result_counters(
                interrupted_result, solved_count, failed_count, skipped_count
            )
        print(f"\n{'!'*72}")
        print(f"  {message} — saving batch progress.")
        print(f"{'!'*72}")

    batch_end = time.time()
    summary_path = _save_batch_progress(args, results, batch_start, finished=True)

    solved_names = [r["challenge"] for r in results if r.get("solved")]
    failed_names = [r["challenge"] for r in results if not r.get("solved") and r.get("status") != "skipped"]
    skipped_names = [r["challenge"] for r in results if r.get("status") == "skipped"]
    interrupted_names = [r["challenge"] for r in results if r.get("status") == "interrupted"]

    print(f"\n{'='*72}")
    print(f"  Batch complete: {len(results)}/{total} attempted")
    print(f"    Solved:  {solved_count}")
    print(f"    Failed:  {failed_count}")
    print(f"    Skipped: {skipped_count}")
    print(f"    Total time: {batch_end - batch_start:.1f}s")
    if solved_names:
        print(f"\n  Solved challenges:")
        for n in solved_names:
            print(f"    + {n}")
    if failed_names:
        print(f"\n  Failed challenges:")
        for n in failed_names:
            print(f"    - {n}")
    if skipped_names:
        print(f"\n  Skipped challenges:")
        for n in skipped_names:
            print(f"    ~ {n}")
    if interrupted_names:
        print(f"\n  Interrupted challenges:")
        for n in interrupted_names:
            print(f"    ! {n}")
    print(f"\n  Summary saved to: {summary_path}")
    print(f"{'='*72}\n")

    if batch_interrupted or interrupted_names:
        return 130
    return 0 if solved_count > 0 or failed_count == 0 else 1


def _save_batch_progress(
    args: argparse.Namespace,
    results: list[dict[str, Any]],
    batch_start: float,
    *,
    finished: bool = False,
) -> Path:
    """Persist a JSON summary of batch progress after each challenge. Returns the summary path."""
    logdir = resolve_experiment_logdir(args)
    summary_path = logdir / "_batch_summary.json"

    solved_list = [r for r in results if r.get("solved")]
    failed_list = [r for r in results if not r.get("solved") and r.get("status") != "skipped"]
    skipped_list = [r for r in results if r.get("status") == "skipped"]
    interrupted_list = [r for r in results if r.get("status") == "interrupted"]

    def _result_log(r: dict[str, Any]) -> dict[str, Any]:
        return _safe_read_json(r.get("logfile")) or {}

    def _result_summary(r: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        summary = r.get("summary")
        if isinstance(summary, dict):
            return summary
        summary = log_payload.get("summary")
        return summary if isinstance(summary, dict) else {}

    def _result_state_metrics(r: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        metrics = r.get("state_metrics")
        if isinstance(metrics, dict) and metrics:
            return metrics
        metrics = log_payload.get("state_metrics")
        if isinstance(metrics, dict) and metrics:
            return metrics
        state_payload = log_payload.get("state")
        return _state_metrics(state_payload if isinstance(state_payload, dict) else None)

    def _result_token_usage(r: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, int]:
        if isinstance(r.get("token_usage"), dict):
            return _token_usage(r.get("token_usage"))
        if isinstance(log_payload.get("token_usage"), dict):
            return _token_usage(log_payload.get("token_usage"))
        summary = _result_summary(r, log_payload)
        return _token_usage(summary.get("token_usage"))

    def _result_challenge_metadata(r: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any]:
        meta = r.get("challenge_metadata")
        if isinstance(meta, dict) and meta:
            return meta
        meta = log_payload.get("challenge_metadata")
        return meta if isinstance(meta, dict) else {}

    def _result_artifacts(r: dict[str, Any], log_payload: dict[str, Any]) -> dict[str, Any] | None:
        artifacts = r.get("artifacts")
        if isinstance(artifacts, dict):
            return artifacts
        artifacts = log_payload.get("artifacts")
        return artifacts if isinstance(artifacts, dict) else None

    def _challenge_entry(r: dict[str, Any]) -> dict[str, Any]:
        log_payload = _result_log(r)
        summary = _result_summary(r, log_payload)
        metadata = _result_challenge_metadata(r, log_payload)
        state_metrics = _result_state_metrics(r, log_payload)
        token_usage = _result_token_usage(r, log_payload)
        artifacts = _result_artifacts(r, log_payload)
        failure_buckets = _failure_buckets(log_payload, r)
        return {
            "challenge": r["challenge"],
            "run_id": r.get("run_id") or summary.get("run_id") or state_metrics.get("run_id"),
            "solved": r.get("solved", False),
            "status": r.get("status", "unknown"),
            "runtime_sec": r.get("runtime_sec"),
            "category": metadata.get("category"),
            "files_count": len(metadata.get("files") or []),
            "has_server": bool(metadata.get("server_name") and metadata.get("port")),
            "server_type": metadata.get("server_type"),
            "authorized_scope_count": len(r.get("authorized_scope") or log_payload.get("authorized_scope") or []),
            "max_cycles": r.get("max_cycles") or log_payload.get("effective_max_cycles"),
            "token_usage": token_usage,
            "state_metrics": state_metrics,
            "artifacts": artifacts,
            "logfile": r.get("logfile"),
            "error_type": r.get("error", {}).get("type") if r.get("error") else None,
            "failure_buckets": failure_buckets,
        }

    details = [_challenge_entry(r) for r in results]
    token_usages = [entry["token_usage"] for entry in details]
    total_token_usage = _sum_numeric_dicts(token_usages)
    solved_token_usages = [entry["token_usage"] for entry in details if entry.get("solved")]
    failed_token_usages = [
        entry["token_usage"]
        for entry in details
        if not entry.get("solved") and entry.get("status") != "skipped"
    ]
    runtime_values = [
        float(entry["runtime_sec"])
        for entry in details
        if isinstance(entry.get("runtime_sec"), (int, float))
    ]
    todo_counts = [
        int((entry.get("state_metrics") or {}).get("todo_count") or 0)
        for entry in details
    ]
    open_todo_counts = [
        int((entry.get("state_metrics") or {}).get("open_todo_count") or 0)
        for entry in details
    ]
    partial_todo_counts = [
        int((entry.get("state_metrics") or {}).get("partial_todo_count") or 0)
        for entry in details
    ]
    interrupted_todo_counts = [
        int((entry.get("state_metrics") or {}).get("interrupted_todo_count") or 0)
        for entry in details
    ]
    worker_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("worker_counts") or {}
        for entry in details
    ])
    todo_status_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("todo_status_counts") or {}
        for entry in details
    ])
    evidence_tool_totals = _sum_numeric_dicts([
        entry.get("state_metrics", {}).get("evidence_tool_counts") or {}
        for entry in details
    ])
    category_counts: dict[str, int] = {}
    failure_bucket_counts: dict[str, int] = {}
    for entry in details:
        category = str(entry.get("category") or "unknown")
        category_counts[category] = category_counts.get(category, 0) + 1
        for bucket in entry.get("failure_buckets") or []:
            failure_bucket_counts[str(bucket)] = failure_bucket_counts.get(str(bucket), 0) + 1

    attempted = len(results)
    success_rate = round(len(solved_list) / attempted, 4) if attempted else 0.0
    elapsed = round(time.time() - batch_start, 3)
    payload = {
        "schema_version": 2,
        "split": args.split,
        "category_filter": getattr(args, "category", None),
        "finished": finished,
        "started_at": _utc_timestamp(batch_start),
        "updated_at": _utc_timestamp(),
        "total_attempted": len(results),
        "solved_count": len(solved_list),
        "failed_count": len(failed_list),
        "skipped_count": len(skipped_list),
        "interrupted_count": len(interrupted_list),
        "success_rate": success_rate,
        "elapsed_sec": elapsed,
        "experiment_config": {
            "name": getattr(args, "name", None),
            "index": getattr(args, "index", None),
            "dataset": getattr(args, "dataset", None),
            "split": args.split,
            "category_filter": getattr(args, "category", None),
            "challenge": getattr(args, "challenge", None),
            "run_all": bool(getattr(args, "run_all", False)),
            "max_cycles_arg": getattr(args, "max_cycles", None),
            "container_image": getattr(args, "container_image", None),
            "container_network": getattr(args, "container_network", None),
            "parallel_workers": int(getattr(args, "parallel_workers", 1) or 1),
            "replicas": int(getattr(args, "replicas", 1) or 1),
            "skip_exist": bool(getattr(args, "skip_exist", False)),
            "quiet": bool(getattr(args, "quiet", False)),
            "debug": bool(getattr(args, "debug", False)),
            "logdir": str(logdir),
            "output_root": getattr(args, "output_root", None),
            "objective_overridden": bool(getattr(args, "objective", None)),
            "scope_overridden": bool(getattr(args, "scope", None)),
            "llm_gateway": _load_llm_experiment_config(),
        },
        "paper_metrics": {
            "success_rate": success_rate,
            "attempted": attempted,
            "solved": len(solved_list),
            "failed": len(failed_list),
            "skipped": len(skipped_list),
            "interrupted": len(interrupted_list),
            "elapsed_sec": elapsed,
            "runtime_sec_total": round(sum(runtime_values), 3),
            "runtime_sec_mean": round(sum(runtime_values) / len(runtime_values), 3) if runtime_values else 0.0,
            "token_usage_total": total_token_usage,
            "token_usage_mean_per_attempt": _avg_token_usage(token_usages),
            "token_usage_mean_solved": _avg_token_usage(solved_token_usages),
            "token_usage_mean_failed": _avg_token_usage(failed_token_usages),
            "todo_count_total": sum(todo_counts),
            "todo_count_mean": round(sum(todo_counts) / len(todo_counts), 3) if todo_counts else 0.0,
            "open_todo_count_total": sum(open_todo_counts),
            "partial_todo_count_total": sum(partial_todo_counts),
            "interrupted_todo_count_total": sum(interrupted_todo_counts),
            "todo_status_totals": todo_status_totals,
            "worker_totals": worker_totals,
            "evidence_tool_totals": evidence_tool_totals,
            "category_counts": category_counts,
            "failure_bucket_counts": failure_bucket_counts,
        },
        "failure_buckets": failure_bucket_counts,
        "token_usage": {
            "total": total_token_usage,
            "mean_per_attempt": _avg_token_usage(token_usages),
            "mean_solved": _avg_token_usage(solved_token_usages),
            "mean_failed": _avg_token_usage(failed_token_usages),
        },
        "solved_challenges": [r["challenge"] for r in solved_list],
        "failed_challenges": [r["challenge"] for r in failed_list],
        "skipped_challenges": [r["challenge"] for r in skipped_list],
        "interrupted_challenges": [r["challenge"] for r in interrupted_list],
        "details": details,
    }
    write_log(summary_path, payload)
    if not finished:
        print(f"  Progress saved to {summary_path}")
    return summary_path


def _update_result_counters(
    result: dict[str, Any],
    solved_count: int,
    failed_count: int,
    skipped_count: int,
) -> tuple[int, int, int]:
    if result.get("status") == "skipped":
        skipped_count += 1
    elif result.get("solved"):
        solved_count += 1
    else:
        failed_count += 1
    return solved_count, failed_count, skipped_count


def _run_named_challenge_worker(args_dict: dict[str, Any], challenge_name: str) -> dict[str, Any]:
    worker_args = argparse.Namespace(**args_dict)
    worker_args.challenge = challenge_name
    try:
        challenge = load_challenge(worker_args)
    except Exception as exc:
        return {
            "challenge": challenge_name,
            "solved": False,
            "status": "load_error",
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "api_error": False,
            "llm_error": False,
        }
    return run_single_challenge(worker_args, challenge)


def run_single_challenge_replicas(args: argparse.Namespace) -> int:
    replicas = max(1, int(getattr(args, "replicas", 1) or 1))
    if replicas == 1:
        challenge = load_challenge(args)
        result = run_single_challenge(args, challenge)
        if result.get("status") == "interrupted":
            print(f"Run interrupted. Log saved to {result.get('logfile')}")
            return 130
        if result.get("error"):
            print(f"Run failed: {result['error']['type']}: {result['error']['message']}")
            print(f"Log saved to {result.get('logfile')}")
            return 1
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 0

    workers = max(1, int(getattr(args, "parallel_workers", replicas) or replicas))
    workers = min(workers, replicas)
    print(f"Launching {replicas} isolated replicas with {workers} workers")

    base_args = vars(args).copy()
    run_label_prefix = str(int(time.time()))
    results: list[dict[str, Any]] = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(_run_single_replica_worker, base_args, idx + 1, run_label_prefix): idx + 1
            for idx in range(replicas)
        }
        for future in concurrent.futures.as_completed(future_map):
            replica_idx = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {
                    "challenge": args.challenge,
                    "replica": replica_idx,
                    "solved": False,
                    "status": "worker_error",
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                    "api_error": isinstance(exc, LLMClientError),
                    "llm_error": isinstance(exc, LLMClientError),
                }
            results.append(result)
            marker = "SOLVED" if result.get("solved") else "FAILED"
            print(f"[Replica {replica_idx}] {marker} status={result.get('status')} log={result.get('logfile')}")
            if result.get("api_error"):
                for pending in future_map:
                    pending.cancel()
                break

    print(json.dumps({"replicas": replicas, "results": results}, indent=2, ensure_ascii=True))
    if any(r.get("status") == "interrupted" for r in results):
        return 130
    if any(r.get("api_error") for r in results):
        return 2
    return 0 if any(r.get("solved") for r in results) else 1


def _run_single_replica_worker(
    args_dict: dict[str, Any],
    replica_idx: int,
    label_prefix: str,
) -> dict[str, Any]:
    worker_args = argparse.Namespace(**args_dict)
    base_name = worker_args.name or "replica"
    worker_args.name = f"{base_name}_rep{replica_idx}_{label_prefix}"
    if worker_args.output_root:
        worker_args.output_root = str(Path(worker_args.output_root).expanduser().resolve() / worker_args.name)
    challenge = load_challenge(worker_args)
    result = run_single_challenge(worker_args, challenge)
    result["replica"] = replica_idx
    return result


def main() -> int:
    if len(sys.argv) > 1:
        args = build_parser().parse_args()
    else:
        args = _args_from_config()

    is_run_all = getattr(args, "run_all", False) or args.challenge == "__all__"

    if is_run_all:
        if not getattr(args, "run_all", False):
            args.run_all = True
        return run_all_challenges(args)

    if not args.challenge:
        print("Error: --challenge is required (or use --run-all to run all challenges)")
        return 2

    return run_single_challenge_replicas(args)


if __name__ == "__main__":
    raise SystemExit(main())
