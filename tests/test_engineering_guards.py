from __future__ import annotations

import ast
import logging
import re
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PRODUCTION_ROOTS = (
    PROJECT_ROOT / "killchain_docker",
    PROJECT_ROOT / "scripts",
    PROJECT_ROOT / "run.py",
    PROJECT_ROOT / "docker_entrypoint.py",
)
CHALLENGE_ID_RE = re.compile(r"\b20\d{2}[fq]-[a-z0-9]+-[a-z0-9_-]+\b")
TRAINING_FIXTURE_LITERAL_RE = re.compile(
    r"\b(?:csawpad|pcapin|stfu|flag\.stfu)\b",
    re.IGNORECASE,
)
EXPERIMENT_LABEL_RE = re.compile(
    r"\b(?:oracle_exec|oracle_e2e|scope_guard|thread_status|codex_style|logging_thread|monitor_heartbeat)_"
    r"[a-z0-9_]*\b"
)
RESERVED_LOG_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__) | {
    "message",
    "asctime",
}
LOG_METHODS = {"debug", "info", "warning", "error", "critical", "exception"}
EXCEPTION_LOG_DELEGATES = {"_debug_decode_failure", "_worker_failure_result"}


def production_python_files() -> list[Path]:
    files: list[Path] = []
    for root in PRODUCTION_ROOTS:
        if root.is_file():
            files.append(root)
            continue
        files.extend(
            path for path in root.rglob("*.py") if "__pycache__" not in path.parts
        )
    return sorted(files)


def test_production_code_does_not_use_print_or_debug_breakpoints() -> None:
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and _is_forbidden_call(node.func):
                violations.append(f"{_rel(path)}:{node.lineno}")

    assert not violations, "forbidden production debug/output calls:\n" + "\n".join(
        violations
    )


def test_stdout_stderr_access_is_centralized() -> None:
    allowed = PROJECT_ROOT / "killchain_docker" / "logging_utils.py"
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for lineno in _sys_stream_lines(tree):
            if path != allowed:
                violations.append(f"{_rel(path)}:{lineno}")

    assert not violations, (
        "direct sys stdout/stderr access must stay in logging_utils:\n"
        + "\n".join(violations)
    )


def test_production_broad_exception_handlers_are_not_silent() -> None:
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ExceptHandler)
                and _is_broad_exception_handler(node)
                and _is_silent_exception_body(node.body)
            ):
                violations.append(f"{_rel(path)}:{node.lineno}")

    assert not violations, "silent broad production exception handlers:\n" + "\n".join(
        violations
    )


def test_production_broad_exception_handlers_log_delegate_or_reraise() -> None:
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(
                node, ast.ExceptHandler
            ) or not _is_broad_exception_handler(node):
                continue
            if _broad_exception_handler_is_accounted_for(node):
                continue
            violations.append(f"{_rel(path)}:{node.lineno}")

    assert not violations, (
        "broad production exception handlers must log with traceback and context, delegate to a "
        "logging helper, or re-raise:\n" + "\n".join(violations)
    )


def test_production_code_has_no_challenge_or_probe_specific_literals() -> None:
    violations: list[str] = []
    for path in production_python_files() + [PROJECT_ROOT / "README.md"]:
        text = path.read_text(encoding="utf-8")
        matches = sorted(
            set(
                CHALLENGE_ID_RE.findall(text)
                + EXPERIMENT_LABEL_RE.findall(text)
                + TRAINING_FIXTURE_LITERAL_RE.findall(text)
            )
        )
        if matches:
            violations.append(f"{_rel(path)}: {', '.join(matches)}")

    assert not violations, (
        "challenge/probe-specific literals in production files:\n"
        + "\n".join(violations)
    )


def test_logging_extra_literals_do_not_override_log_record_fields() -> None:
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            reserved = _reserved_extra_literal_keys(node)
            if reserved:
                keys = ", ".join(sorted(reserved))
                violations.append(f"{_rel(path)}:{node.lineno}: {keys}")

    assert not violations, (
        "logging extra overrides reserved LogRecord fields:\n" + "\n".join(violations)
    )


def test_exception_logs_include_structured_context() -> None:
    violations: list[str] = []
    for path in production_python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not _is_exception_context_log_call(node):
                continue
            if _has_extra_context(node):
                continue
            violations.append(f"{_rel(path)}:{node.lineno}")

    assert not violations, (
        "exception logs missing structured extra context:\n" + "\n".join(violations)
    )


def test_executable_logging_entrypoints_configure_standard_logging() -> None:
    violations: list[str] = []
    for path in production_python_files():
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        if not _has_main_guard(tree) or not _uses_standard_logger(tree):
            continue
        if "configure_logging(" not in source:
            violations.append(_rel(path))

    assert not violations, (
        "executable logging entrypoints missing configure_logging:\n"
        + "\n".join(violations)
    )


def test_scripts_directory_has_no_legacy_shell_entrypoints() -> None:
    scripts_dir = PROJECT_ROOT / "scripts"
    violations = sorted(path.name for path in scripts_dir.glob("*.sh"))

    assert not violations, (
        "legacy shell entrypoints must be replaced by logged Python scripts:\n"
        + "\n".join(violations)
    )


def test_docker_execution_image_uses_logged_python_entrypoint() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    entrypoint_path = PROJECT_ROOT / "docker_entrypoint.py"
    entrypoint = entrypoint_path.read_text(encoding="utf-8")

    assert not (PROJECT_ROOT / "docker_entrypoint.sh").exists()
    assert "COPY docker_entrypoint.py /home/$USERNAME/.entrypoint.py" in dockerfile
    assert 'CMD ["python3", "/home/ctfplayer/.entrypoint.py"]' in dockerfile
    assert "ThreadingHTTPServer" in entrypoint
    assert "logging.basicConfig" in entrypoint

    forbidden = [
        "/tmp/ctf_web.log",
        "sleep infinity",
        "python3 -u -m http.server",
    ]
    violations = [value for value in forbidden if value in dockerfile + entrypoint]
    assert not violations, "legacy docker entrypoint fragments remain:\n" + "\n".join(
        violations
    )


def test_docker_execution_image_includes_barcode_decoders() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    for package in (
        "libzxing-core-java",
        "libzxing-javase-java",
        "zbar-tools",
        "python3-pyzbar",
    ):
        assert package in dockerfile
    assert "com.google.zxing.client.j2se.CommandLineRunner" in dockerfile
    assert "/usr/local/bin/zxing" in dockerfile


def test_docker_execution_image_includes_disk_forensics_tools() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    for package in ("fdisk", "sleuthkit", "foremost"):
        assert package in dockerfile


def test_documented_runtime_commands_use_autopentest_conda_env() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    setup = (PROJECT_ROOT / "setup.sh").read_text(encoding="utf-8")

    direct_readme = re.findall(
        r"(?m)^(?!conda run -n autopentest )"
        r"python (?:run\.py|scripts/|-m http\.server).*$",
        readme,
    )
    direct_setup_pip = re.findall(r"(?m)^\s*pip\s+install\s+--editable\b.*$", setup)

    assert not direct_readme, (
        "README has direct Python runtime commands:\n" + "\n".join(direct_readme)
    )
    assert not direct_setup_pip, (
        "setup.sh has bare editable pip install:\n" + "\n".join(direct_setup_pip)
    )
    assert (
        'conda run -n "$conda_env" python -m pip install --editable "$repo_root"'
        in setup
    )


def _sys_stream_lines(tree: ast.AST) -> list[int]:
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _is_sys_stream_attribute(node):
            lines.append(node.lineno)
        if isinstance(node, ast.ImportFrom) and node.module == "sys":
            if any(alias.name in {"stdout", "stderr"} for alias in node.names):
                lines.append(node.lineno)
    return lines


def _is_sys_stream_attribute(node: ast.Attribute) -> bool:
    return (
        node.attr in {"stdout", "stderr"}
        and isinstance(node.value, ast.Name)
        and node.value.id == "sys"
    )


def _is_forbidden_call(func: ast.expr) -> bool:
    if isinstance(func, ast.Name):
        return func.id in {"print", "breakpoint"}
    if not isinstance(func, ast.Attribute):
        return False
    if func.attr != "set_trace":
        return False
    return isinstance(func.value, ast.Name) and func.value.id in {"pdb", "ipdb"}


def _is_broad_exception_handler(node: ast.ExceptHandler) -> bool:
    if node.type is None:
        return True
    return _is_broad_exception_type(node.type)


def _is_broad_exception_type(node: ast.expr) -> bool:
    if isinstance(node, ast.Name):
        return node.id in {"Exception", "BaseException"}
    if isinstance(node, ast.Tuple):
        return any(_is_broad_exception_type(item) for item in node.elts)
    return False


def _is_silent_exception_body(body: list[ast.stmt]) -> bool:
    if len(body) != 1:
        return False
    statement = body[0]
    if isinstance(statement, (ast.Pass, ast.Continue)):
        return True
    if not isinstance(statement, ast.Return):
        return False
    if statement.value is None:
        return True
    if isinstance(statement.value, ast.Constant) and statement.value.value is None:
        return True
    return isinstance(statement.value, ast.List) and not statement.value.elts


def _broad_exception_handler_is_accounted_for(node: ast.ExceptHandler) -> bool:
    if _contains_raise(node.body):
        return True
    if _contains_exception_log(node.body):
        return True
    return bool(node.name and _delegates_exception(node.body, node.name))


def _contains_raise(body: list[ast.stmt]) -> bool:
    return any(
        isinstance(child, ast.Raise)
        for statement in body
        for child in ast.walk(statement)
    )


def _contains_exception_log(body: list[ast.stmt]) -> bool:
    return any(
        isinstance(child, ast.Call)
        and _is_exception_log_call(child)
        and _has_extra_context(child)
        for statement in body
        for child in ast.walk(statement)
    )


def _is_exception_log_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in LOG_METHODS:
        return False
    if func.attr == "exception":
        return True
    return any(
        keyword.arg == "exc_info"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _is_exception_context_log_call(node: ast.Call) -> bool:
    func = node.func
    if not isinstance(func, ast.Attribute) or func.attr not in LOG_METHODS:
        return False
    if func.attr == "exception":
        return True
    return any(
        keyword.arg == "exc_info" and not _is_falsey_literal(keyword.value)
        for keyword in node.keywords
    )


def _is_falsey_literal(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and node.value in {False, None}


def _has_extra_context(node: ast.Call) -> bool:
    return any(keyword.arg == "extra" for keyword in node.keywords)


def _delegates_exception(body: list[ast.stmt], exception_name: str) -> bool:
    return any(
        isinstance(child, ast.Call)
        and _call_name(child.func) in EXCEPTION_LOG_DELEGATES
        and any(
            isinstance(arg, ast.Name) and arg.id == exception_name for arg in child.args
        )
        for statement in body
        for child in ast.walk(statement)
    )


def _call_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _reserved_extra_literal_keys(node: ast.Call) -> set[str]:
    extra = next((kw.value for kw in node.keywords if kw.arg == "extra"), None)
    if not isinstance(extra, ast.Dict):
        return set()
    keys = {
        key.value
        for key in extra.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    return keys & RESERVED_LOG_RECORD_KEYS


def _has_main_guard(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.If) and _is_main_guard_test(node.test)
        for node in ast.walk(tree)
    )


def _is_main_guard_test(node: ast.expr) -> bool:
    if not isinstance(node, ast.Compare):
        return False
    if len(node.ops) != 1 or not isinstance(node.ops[0], ast.Eq):
        return False
    if len(node.comparators) != 1:
        return False
    left = node.left
    right = node.comparators[0]
    return (
        isinstance(left, ast.Name)
        and left.id == "__name__"
        and isinstance(right, ast.Constant)
        and right.value == "__main__"
    )


def _uses_standard_logger(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call)
        and _call_name(node.func) in {"get_logger", "getLogger"}
        for node in ast.walk(tree)
    )


def _rel(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()
