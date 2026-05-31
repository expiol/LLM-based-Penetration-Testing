"""Runtime guard and execution policy for script.exec."""

from __future__ import annotations

import ast
import io
import re
import tokenize


PYTHON_RANGE_LIMIT = 5000000
PYTHON_SCRIPT_RUNTIME_LIMIT_S = 0
PYTHON_SOCKET_DEFAULT_TIMEOUT_S = 5
NETWORK_SCRIPT_TIMEOUT_CAP_S = 45

NETWORK_SCRIPT_RE = re.compile(
    r"\b(?:socket|telnetlib|http\.client|urllib|requests|pexpect|pwntools|pwn|remote|create_connection|connect|nc|netcat|socat)\b",
    re.IGNORECASE,
)
PYTHON_NETWORK_IMPORTS = {
    "http.client",
    "pexpect",
    "pwn",
    "pwntools",
    "requests",
    "socket",
    "telnetlib",
    "urllib",
    "urllib.request",
}
PYTHON_NETWORK_CALLS = {"connect", "create_connection", "remote", "urlopen"}


def script_uses_network_io(code: str, language: str) -> bool:
    if language == "python":
        return python_script_uses_network_io(code)
    if language in {"bash", "sh"}:
        return bool(NETWORK_SCRIPT_RE.search(code))
    return False


def python_scope_scan_text(code: str) -> str:
    try:
        tokens = tokenize.generate_tokens(io.StringIO(code).readline)
        kept: list[str] = []
        for token in tokens:
            if token.type == tokenize.COMMENT:
                continue
            kept.append(token.string)
        return " ".join(kept)
    except tokenize.TokenError:
        return code


def python_script_uses_network_io(code: str) -> bool:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return bool(NETWORK_SCRIPT_RE.search(python_scope_scan_text(code)))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.lower()
                if (
                    name in PYTHON_NETWORK_IMPORTS
                    or name.split(".", 1)[0] in PYTHON_NETWORK_IMPORTS
                ):
                    return True
        elif isinstance(node, ast.ImportFrom):
            module = (node.module or "").lower()
            if (
                module in PYTHON_NETWORK_IMPORTS
                or module.split(".", 1)[0] in PYTHON_NETWORK_IMPORTS
            ):
                return True
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id.lower() in PYTHON_NETWORK_CALLS:
                return True
            if isinstance(func, ast.Attribute):
                attr = func.attr.lower()
                if attr in PYTHON_NETWORK_CALLS:
                    return True
    return False


def effective_timeout_s(request_timeout_s: int, code: str, language: str) -> int:
    timeout_s = max(1, int(request_timeout_s))
    if script_uses_network_io(code, language):
        return min(timeout_s, NETWORK_SCRIPT_TIMEOUT_CAP_S)
    return timeout_s


def python_runtime_guard_wrapper(timeout_s: int) -> str:
    runtime_limit_s = 0
    if timeout_s > 2:
        runtime_limit_s = timeout_s - 1
        if PYTHON_SCRIPT_RUNTIME_LIMIT_S > 0:
            runtime_limit_s = min(runtime_limit_s, PYTHON_SCRIPT_RUNTIME_LIMIT_S)
    socket_timeout_s = min(PYTHON_SOCKET_DEFAULT_TIMEOUT_S, max(1, timeout_s - 2))
    return f"""import builtins as _kc_builtins
import itertools as _kc_itertools
import linecache as _kc_linecache
import runpy as _kc_runpy
import signal as _kc_signal
import socket as _kc_socket
import sys as _kc_sys
_kc_original_range = _kc_builtins.range
_kc_original_product = _kc_itertools.product
_kc_range_limit = {PYTHON_RANGE_LIMIT}
_kc_runtime_limit_s = {runtime_limit_s}
_kc_socket.setdefaulttimeout({socket_timeout_s})

def _kc_int_locals(_kc_frame):
    if _kc_frame is None:
        return ""
    _kc_items = []
    for _kc_name, _kc_value in sorted(_kc_frame.f_locals.items()):
        if isinstance(_kc_value, int) and abs(_kc_value) >= _kc_range_limit:
            _kc_items.append(f"{{_kc_name}}={{_kc_value}}")
        if len(_kc_items) >= 8:
            break
    return ", ".join(_kc_items)

def _kc_source_line(_kc_frame):
    _kc_lineno = _kc_frame.f_lineno
    _kc_line = _kc_linecache.getline(
        _kc_frame.f_code.co_filename, _kc_lineno
    ).strip()
    if _kc_line in {"pass", "..."} and _kc_lineno > 1:
        _kc_prev_line = _kc_linecache.getline(
            _kc_frame.f_code.co_filename, _kc_lineno - 1
        ).strip()
        if _kc_prev_line.startswith(("while ", "for ", "if ", "elif ", "else:", "try:", "except ", "finally:", "with ")):
            return _kc_lineno - 1, _kc_prev_line
    return _kc_lineno, _kc_line

def _kc_callsite(_kc_frame):
    if _kc_frame is None:
        return ""
    _kc_lineno, _kc_line = _kc_source_line(_kc_frame)
    _kc_locals = _kc_int_locals(_kc_frame)
    _kc_parts = [f"line {{_kc_lineno}}"]
    if _kc_line:
        _kc_parts.append(f"code={{_kc_line!r}}")
    if _kc_locals:
        _kc_parts.append(f"large_int_locals={{_kc_locals}}")
    return "; ".join(_kc_parts)

def _kc_timeout(_signum, _frame):
    _kc_where = _kc_callsite(_frame)
    _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
    raise RuntimeError(
        "script.exec Python time limit exceeded"
        f"{{_kc_suffix}}; use bounded loops or fast-forward math"
    )

_kc_original_signal = _kc_signal.signal
_kc_original_alarm = getattr(_kc_signal, "alarm", None)
_kc_original_setitimer = getattr(_kc_signal, "setitimer", None)
_kc_user_sigalrm_handler = None

def _kc_dispatch_sigalrm(_kc_signum, _kc_frame):
    _kc_handler = _kc_user_sigalrm_handler
    if _kc_handler not in (None, _kc_signal.SIG_DFL, _kc_signal.SIG_IGN):
        _kc_handler(_kc_signum, _kc_frame)
    _kc_timeout(_kc_signum, _kc_frame)

def _kc_clamped_alarm_seconds(_kc_seconds):
    if not _kc_runtime_limit_s:
        return _kc_seconds
    try:
        _kc_seconds_f = float(_kc_seconds)
    except (TypeError, ValueError):
        return _kc_seconds
    if _kc_seconds_f <= 0:
        return _kc_seconds
    _kc_cap = max(1, _kc_runtime_limit_s - 1)
    if _kc_seconds_f >= _kc_runtime_limit_s:
        return _kc_cap
    return _kc_seconds

def _kc_guarded_alarm(_kc_seconds):
    return _kc_original_alarm(_kc_clamped_alarm_seconds(_kc_seconds))

def _kc_guarded_setitimer(_kc_which, _kc_seconds, _kc_interval=0.0):
    if _kc_which == _kc_signal.ITIMER_REAL:
        _kc_seconds = _kc_clamped_alarm_seconds(_kc_seconds)
    return _kc_original_setitimer(_kc_which, _kc_seconds, _kc_interval)

def _kc_guarded_signal(_kc_signum, _kc_handler):
    global _kc_user_sigalrm_handler
    if _kc_signum == _kc_signal.SIGALRM and _kc_runtime_limit_s:
        _kc_previous = _kc_user_sigalrm_handler
        _kc_user_sigalrm_handler = _kc_handler
        _kc_original_signal(_kc_signum, _kc_dispatch_sigalrm)
        return _kc_previous if _kc_previous is not None else _kc_timeout
    return _kc_original_signal(_kc_signum, _kc_handler)

if _kc_runtime_limit_s:
    _kc_signal.signal(_kc_signal.SIGALRM, _kc_timeout)
    _kc_signal.setitimer(_kc_signal.ITIMER_REAL, _kc_runtime_limit_s)
    _kc_signal.signal = _kc_guarded_signal
    if _kc_original_alarm is not None:
        _kc_signal.alarm = _kc_guarded_alarm
    if _kc_original_setitimer is not None:
        _kc_signal.setitimer = _kc_guarded_setitimer

def _kc_guarded_range(*args):
    _kc_range = _kc_original_range(*args)
    _kc_frame = _kc_sys._getframe(1)
    if _kc_frame.f_code.co_filename != globals().get("_kc_script_path"):
        return _kc_range
    try:
        _kc_size = len(_kc_range)
    except OverflowError as _kc_exc:
        _kc_where = _kc_callsite(_kc_frame)
        _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
        raise RuntimeError(
            "range too large for script.exec"
            f"{{_kc_suffix}}; use fast-forward math or bounded sampling"
        ) from _kc_exc
    if _kc_size > _kc_range_limit:
        _kc_where = _kc_callsite(_kc_frame)
        _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
        raise RuntimeError(
            f"range too large for script.exec: {{_kc_size}} > {{_kc_range_limit}}; "
            f"{{_kc_suffix}}; "
            "use fast-forward math or bounded sampling"
        )
    return _kc_range

_kc_builtins.range = _kc_guarded_range

def _kc_guarded_product(*_kc_iterables, repeat=1):
    _kc_frame = _kc_sys._getframe(1)
    if _kc_frame.f_code.co_filename != globals().get("_kc_script_path"):
        return _kc_original_product(*_kc_iterables, repeat=repeat)
    try:
        _kc_repeat = int(repeat)
    except (TypeError, ValueError) as _kc_exc:
        raise RuntimeError("itertools.product repeat must be an integer") from _kc_exc
    if _kc_repeat < 0:
        raise ValueError("repeat argument cannot be negative")
    _kc_lengths = []
    for _kc_iterable in _kc_iterables:
        try:
            _kc_lengths.append(len(_kc_iterable))
        except TypeError:
            return _kc_original_product(*_kc_iterables, repeat=repeat)
    _kc_size = 1
    for _ in _kc_original_range(_kc_repeat):
        for _kc_length in _kc_lengths:
            _kc_size *= _kc_length
            if _kc_size > _kc_range_limit:
                _kc_where = _kc_callsite(_kc_frame)
                _kc_suffix = f" at {{_kc_where}}" if _kc_where else ""
                raise RuntimeError(
                    f"product too large for script.exec: {{_kc_size}} > {{_kc_range_limit}}; "
                    f"{{_kc_suffix}}; "
                    "use fast-forward math or bounded sampling"
                )
    return _kc_original_product(*_kc_iterables, repeat=repeat)

_kc_itertools.product = _kc_guarded_product
del _kc_guarded_range, _kc_guarded_product, _kc_builtins, _kc_itertools

if len(_kc_sys.argv) < 2:
    raise RuntimeError("script.exec wrapper missing script path")
_kc_script_path = _kc_sys.argv[1]
_kc_sys.argv = [_kc_script_path, *_kc_sys.argv[2:]]
_kc_runpy.run_path(_kc_script_path, run_name="__main__")

"""
