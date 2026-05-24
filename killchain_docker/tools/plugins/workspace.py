"""Shell snippets for protected command workspaces.

The execution plane runs commands inside the challenge container via
``bash -c``.  These helpers keep the shell wrapping logic in one place:
snapshot the challenge files, run the requested command, restore originals,
and clean temporary files.
"""

from __future__ import annotations

import shlex

from killchain_docker.state.constants import DEFAULT_FILES_ROOT


_DEFAULT_WORKSPACE_MAX_MB = 512
_DEFAULT_MEMORY_MAX_MB = 3072
_DEFAULT_CPU_MAX_S = 0


def protected_shell_command(
    command: str,
    files_root: object,
    *,
    max_workspace_mb: object | None = None,
    max_memory_mb: object | None = None,
    max_cpu_s: object | None = None,
    preserve_relative_paths: tuple[str, ...] | list[str] | None = None,
) -> str:
    """Return a ``bash -c`` command that restores ``files_root`` on exit."""

    root = shlex.quote(str(files_root or DEFAULT_FILES_ROOT))
    user_command = shlex.quote(command)
    max_kb = _workspace_limit_kb(max_workspace_mb)
    memory_kb = _memory_limit_kb(max_memory_mb)
    cpu_s = _cpu_limit_s(max_cpu_s)
    preserve_exports = _preserve_exports(preserve_relative_paths)
    return _join_shell(
        f"_kc_root={root};",
        f"_kc_user_command={user_command};",
        f"_kc_workspace_limit_kb={max_kb};",
        f"_kc_memory_limit_kb={memory_kb};",
        f"_kc_cpu_limit_s={cpu_s};",
        preserve_exports,
        _stale_workspace_cleanup(),
        '_kc_tmp=$(mktemp -d /tmp/_shell_exec_XXXXXX) || exit 1;',
        '_kc_budget_flag="$_kc_tmp/workspace_budget_exceeded";',
        '_kc_backup="$_kc_tmp/original";',
        '_kc_original="$_kc_tmp/original_ro";',
        '_kc_preserve="$_kc_tmp/preserve";',
        '_kc_scratch="$_kc_tmp/scratch";',
        'mkdir -p "$_kc_backup" "$_kc_original" "$_kc_preserve" "$_kc_scratch" || exit 1;',
        _restore_function(),
        _workspace_budget_functions(),
        '_kc_cleanup() { _kc_rc=$?; _kc_stop_workspace_monitor; _kc_restore; rm -rf "$_kc_tmp"; exit $_kc_rc; };',
        'trap _kc_cleanup EXIT INT TERM;',
        'if [ -d "$_kc_root" ]; then',
        '  _kc_had_root=1;',
        '  cp -a "$_kc_root"/. "$_kc_backup"/ || exit 1;',
        '  cp -a "$_kc_root"/. "$_kc_original"/ || exit 1;',
        '  cd "$_kc_root" || exit 1;',
        'else',
        '  _kc_had_root=0;',
        'fi;',
        'export CTF_FILES_ROOT="$_kc_root";',
        'export CTF_ORIGINAL_FILES_ROOT="$_kc_original";',
        'export CTF_TEMP_DIR="$_kc_scratch";',
        'export TMPDIR="$_kc_scratch";',
        'export TMP="$_kc_scratch";',
        'export TEMP="$_kc_scratch";',
        '_kc_run_monitored "$_kc_root" "$_kc_scratch" -- bash -c "$_kc_user_command"',
    )


def disposable_script_command(
    *,
    files_root: object,
    interpreter_cmd: str,
    guard_source: str | None = None,
    max_workspace_mb: object | None = None,
    max_memory_mb: object | None = None,
    max_cpu_s: object | None = None,
) -> str:
    """Return a ``bash -c`` command for stdin-provided generated scripts.

    The generated script is read from stdin into a temporary file.  Challenge
    files are copied into a disposable work directory, and the script starts in
    that directory with ``CTF_FILES_ROOT`` pointing to the copy.
    """

    root = shlex.quote(str(files_root or DEFAULT_FILES_ROOT))
    max_kb = _workspace_limit_kb(max_workspace_mb)
    memory_kb = _memory_limit_kb(max_memory_mb)
    cpu_s = _cpu_limit_s(max_cpu_s)
    runner = f"{interpreter_cmd} \"$_kc_script\""
    if guard_source is not None:
        runner = _join_shell(
            f"printf %s {shlex.quote(guard_source)} > \"$_kc_guard\" || exit 1;",
            f"{interpreter_cmd} \"$_kc_guard\" \"$_kc_script\"",
        )

    return _join_shell(
        f"_kc_root={root};",
        f"_kc_workspace_limit_kb={max_kb};",
        f"_kc_memory_limit_kb={memory_kb};",
        f"_kc_cpu_limit_s={cpu_s};",
        _stale_workspace_cleanup(),
        '_kc_tmp=$(mktemp -d /tmp/_script_exec_XXXXXX) || exit 1;',
        '_kc_budget_flag="$_kc_tmp/workspace_budget_exceeded";',
        '_kc_script="$_kc_tmp/_script_main";',
        '_kc_guard="$_kc_tmp/_script_guard.py";',
        '_kc_work="$_kc_tmp/work";',
        '_kc_backup="$_kc_tmp/original";',
        '_kc_original="$_kc_tmp/original_ro";',
        '_kc_preserve="$_kc_tmp/preserve";',
        '_kc_scratch="$_kc_tmp/scratch";',
        '_kc_artifacts="$_kc_root/.autopentest_artifacts";',
        '_kc_art_dir="$_kc_artifacts/script_$$_$(date +%s)";',
        '_kc_preserve_paths=\'.autopentest_artifacts\';',
        'mkdir -p "$_kc_work" "$_kc_backup" "$_kc_original" "$_kc_preserve" "$_kc_scratch" || exit 1;',
        'cat > "$_kc_script" || exit 1;',
        _restore_function(),
        _script_artifact_publish_function(),
        _workspace_budget_functions(),
        '_kc_cleanup() { _kc_rc=$?; _kc_stop_workspace_monitor; _kc_restore; rm -rf "$_kc_tmp"; exit $_kc_rc; };',
        'trap _kc_cleanup EXIT INT TERM;',
        'if [ -d "$_kc_root" ]; then',
        '  _kc_had_root=1;',
        '  cp -a "$_kc_root"/. "$_kc_backup"/ || exit 1;',
        '  cp -a "$_kc_root"/. "$_kc_original"/ || exit 1;',
        '  cp -a "$_kc_root"/. "$_kc_work"/ || exit 1;',
        'else',
        '  _kc_had_root=0;',
        'fi;',
        'export CTF_FILES_ROOT="$_kc_work";',
        'export CTF_ORIGINAL_FILES_ROOT="$_kc_original";',
        'export CTF_TEMP_DIR="$_kc_scratch";',
        'export CTF_ARTIFACTS_DIR="$_kc_art_dir/manual";',
        'export TMPDIR="$_kc_scratch";',
        'export TMP="$_kc_scratch";',
        'export TEMP="$_kc_scratch";',
        'cd "$_kc_work" || exit 1;',
        'export _kc_script _kc_guard _kc_work _kc_backup _kc_original _kc_scratch _kc_root _kc_tmp _kc_budget_flag _kc_workspace_limit_kb _kc_artifacts _kc_art_dir;',
        f'_kc_run_monitored "$_kc_work" "$_kc_scratch" -- sh -c {shlex.quote(runner)};',
        '_kc_rc=$?;',
        '_kc_publish_script_artifacts;',
        'exit "$_kc_rc";',
    )


def _restore_function() -> str:
    return _join_shell(
        '_kc_restore() {',
        '  if [ "${_kc_had_root:-0}" = 1 ]; then',
        '    if [ -n "${_kc_preserve:-}" ]; then',
        '      rm -rf "$_kc_preserve" 2>/dev/null || true;',
        '      mkdir -p "$_kc_preserve";',
        '    fi;',
        '    if [ -n "${_kc_preserve:-}" ] && [ -n "${_kc_preserve_paths:-}" ]; then',
        '      for _kc_rel in $_kc_preserve_paths; do',
        '        case "$_kc_rel" in ""|/*|*..*) continue ;; esac;',
        '        if [ -e "$_kc_root/$_kc_rel" ]; then',
        '          mkdir -p "$_kc_preserve/$(dirname "$_kc_rel")";',
        '          cp -a "$_kc_root/$_kc_rel" "$_kc_preserve/$_kc_rel" 2>/dev/null || true;',
        '        fi;',
        '      done;',
        '    fi;',
        '    mkdir -p "$_kc_root";',
        '    find "$_kc_root" -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true;',
        '    cp -a "$_kc_backup"/. "$_kc_root"/ 2>/dev/null || true;',
        '    if [ -n "${_kc_preserve:-}" ] && [ -n "${_kc_preserve_paths:-}" ]; then',
        '      for _kc_rel in $_kc_preserve_paths; do',
        '        case "$_kc_rel" in ""|/*|*..*) continue ;; esac;',
        '        if [ -e "$_kc_preserve/$_kc_rel" ]; then',
        '          mkdir -p "$_kc_root/$(dirname "$_kc_rel")";',
        '          rm -rf "$_kc_root/$_kc_rel" 2>/dev/null || true;',
        '          cp -a "$_kc_preserve/$_kc_rel" "$_kc_root/$(dirname "$_kc_rel")"/ 2>/dev/null || true;',
        '        fi;',
        '      done;',
        '    fi;',
        '  fi;',
        '};',
    )


def _stale_workspace_cleanup() -> str:
    return _join_shell(
        "find /tmp -maxdepth 1 \\( -name '_script_exec_*' -o -name '_shell_exec_*' \\) "
        "-mmin +30 -exec rm -rf -- {} + 2>/dev/null || true;"
    )


def _script_artifact_publish_function() -> str:
    return _join_shell(
        '_kc_publish_one_artifact() {',
        '  _kc_src="$1"; _kc_origin="$2"; _kc_rel="$3";',
        '  case "$_kc_rel" in ""|/*|*..*) return 0 ;; esac;',
        '  if [ ! -f "$_kc_src" ]; then return 0; fi;',
        '  _kc_size=$(stat -c%s "$_kc_src" 2>/dev/null || stat -f%z "$_kc_src" 2>/dev/null || echo 0);',
        '  _kc_size_kb=$(((_kc_size + 1023) / 1024));',
        '  if [ "$_kc_size_kb" -gt 32768 ]; then return 0; fi;',
        '  if [ "$_kc_art_count" -ge 40 ]; then return 0; fi;',
        '  if [ $((_kc_art_total_kb + _kc_size_kb)) -gt 65536 ]; then return 0; fi;',
        '  _kc_dest="$_kc_art_dir/$_kc_origin/$_kc_rel";',
        '  mkdir -p "$(dirname "$_kc_dest")" || return 0;',
        '  if [ "$_kc_src" != "$_kc_dest" ]; then cp -a "$_kc_src" "$_kc_dest" 2>/dev/null || return 0; fi;',
        '  _kc_digest=$(sha256sum "$_kc_src" 2>/dev/null | awk \'{print $1}\');',
        '  if [ -z "$_kc_digest" ]; then _kc_digest=$(shasum -a 256 "$_kc_src" 2>/dev/null | awk \'{print $1}\'); fi;',
        '  _kc_file_type=$(file -b "$_kc_src" 2>/dev/null | tr "\\t\\r\\n" "   ");',
        '  _kc_mime_type=$(file -b --mime-type "$_kc_src" 2>/dev/null | tr "\\t\\r\\n" "   ");',
        '  printf "%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n" "$_kc_dest" "$_kc_size" "$_kc_origin" "$_kc_rel" "$_kc_digest" "$_kc_file_type" "$_kc_mime_type" >> "$_kc_manifest";',
        '  _kc_art_count=$((_kc_art_count + 1));',
        '  _kc_art_total_kb=$((_kc_art_total_kb + _kc_size_kb));',
        '};',
        '_kc_publish_script_artifacts() {',
        '  if [ "${_kc_had_root:-0}" != 1 ]; then return 0; fi;',
        '  _kc_manifest="$_kc_tmp/script_artifacts.tsv";',
        '  _kc_art_count=0; _kc_art_total_kb=0;',
        '  mkdir -p "$_kc_art_dir/scratch" "$_kc_art_dir/manual" 2>/dev/null || return 0;',
        '  if [ -d "$_kc_scratch" ]; then',
        '    while IFS= read -r -d "" _kc_src; do',
        '      _kc_rel="${_kc_src#$_kc_scratch/}";',
        '      _kc_publish_one_artifact "$_kc_src" "scratch" "$_kc_rel";',
        '    done < <(find "$_kc_scratch" -type f -print0 2>/dev/null);',
        '  fi;',
        '  if [ -d "$_kc_art_dir/manual" ]; then',
        '    while IFS= read -r -d "" _kc_src; do',
        '      _kc_rel="${_kc_src#$_kc_art_dir/manual/}";',
        '      _kc_publish_one_artifact "$_kc_src" "manual" "$_kc_rel";',
        '    done < <(find "$_kc_art_dir/manual" -type f -print0 2>/dev/null);',
        '  fi;',
        '  if [ -d "$_kc_work" ]; then',
        '    while IFS= read -r -d "" _kc_src; do',
        '      _kc_rel="${_kc_src#$_kc_work/}";',
        '      case "$_kc_rel" in .autopentest_artifacts/*) continue ;; esac;',
        '      _kc_orig="$_kc_original/$_kc_rel";',
        '      if [ -f "$_kc_orig" ] && cmp -s "$_kc_src" "$_kc_orig"; then continue; fi;',
        '      _kc_publish_one_artifact "$_kc_src" "work" "$_kc_rel";',
        '    done < <(find "$_kc_work" -type f -print0 2>/dev/null);',
        '  fi;',
        '  if [ -s "$_kc_manifest" ]; then',
        '    printf "\\n__KILLCHAIN_SCRIPT_ARTIFACTS__\\n";',
        '    cat "$_kc_manifest";',
        '    printf "__KILLCHAIN_SCRIPT_ARTIFACTS_END__\\n";',
        '  else',
        '    rmdir "$_kc_art_dir/manual" "$_kc_art_dir/scratch" "$_kc_art_dir" 2>/dev/null || true;',
        '  fi;',
        '};',
    )


def _workspace_budget_functions() -> str:
    return _join_shell(
        '_kc_du_kb() { du -sk "$@" 2>/dev/null | awk \'{s += $1} END {print s + 0}\'; };',
        '_kc_stop_workspace_monitor() { if [ -n "${_kc_monitor_pid:-}" ]; then kill "$_kc_monitor_pid" 2>/dev/null || true; wait "$_kc_monitor_pid" 2>/dev/null || true; unset _kc_monitor_pid; fi; };',
        '_kc_apply_resource_limits() {',
        '  if [ "${_kc_memory_limit_kb:-0}" -gt 0 ]; then ulimit -v "$_kc_memory_limit_kb" 2>/dev/null || true; fi;',
        '  if [ "${_kc_cpu_limit_s:-0}" -gt 0 ]; then ulimit -t "$_kc_cpu_limit_s" 2>/dev/null || true; fi;',
        '};',
        '_kc_start_workspace_monitor() {',
        '  _kc_baseline_kb=$(_kc_du_kb "$@");',
        '  (',
        '    while :; do',
        '      sleep 1;',
        '      _kc_now_kb=$(_kc_du_kb "$@");',
        '      _kc_growth_kb=$((_kc_now_kb - _kc_baseline_kb));',
        '      if [ "$_kc_growth_kb" -gt "$_kc_workspace_limit_kb" ]; then',
        '        echo "[killchain workspace budget exceeded: ${_kc_growth_kb}KB > ${_kc_workspace_limit_kb}KB]" >&2;',
        '        : > "$_kc_budget_flag";',
        '        kill -TERM "$_kc_runner_pid" 2>/dev/null || true;',
        '        sleep 2;',
        '        kill -KILL "$_kc_runner_pid" 2>/dev/null || true;',
        '        exit 0;',
        '      fi;',
        '    done',
        '  ) &',
        '  _kc_monitor_pid=$!;',
        '};',
        '_kc_run_monitored() {',
        '  _kc_paths=();',
        '  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do _kc_paths+=("$1"); shift; done;',
        '  shift;',
        '  ( _kc_apply_resource_limits; exec "$@" ) &',
        '  _kc_runner_pid=$!;',
        '  _kc_start_workspace_monitor "${_kc_paths[@]}";',
        '  wait "$_kc_runner_pid";',
        '  _kc_rc=$?;',
        '  _kc_stop_workspace_monitor;',
        '  if [ -f "$_kc_budget_flag" ]; then return 125; fi;',
        '  return "$_kc_rc";',
        '};',
    )


def _workspace_limit_kb(value: object | None) -> int:
    try:
        mb = int(value) if value is not None else _DEFAULT_WORKSPACE_MAX_MB
    except (TypeError, ValueError):
        mb = _DEFAULT_WORKSPACE_MAX_MB
    if mb <= 0:
        mb = _DEFAULT_WORKSPACE_MAX_MB
    return mb * 1024


def _memory_limit_kb(value: object | None) -> int:
    try:
        mb = int(value) if value is not None else _DEFAULT_MEMORY_MAX_MB
    except (TypeError, ValueError):
        mb = _DEFAULT_MEMORY_MAX_MB
    if mb < 0:
        mb = _DEFAULT_MEMORY_MAX_MB
    return mb * 1024


def _cpu_limit_s(value: object | None) -> int:
    try:
        seconds = int(value) if value is not None else _DEFAULT_CPU_MAX_S
    except (TypeError, ValueError):
        seconds = _DEFAULT_CPU_MAX_S
    return max(0, seconds)


def _preserve_exports(paths: tuple[str, ...] | list[str] | None) -> str:
    values: list[str] = []
    for raw in paths or ():
        rel = str(raw).strip().strip("/")
        if not rel or ".." in rel or rel.startswith("/"):
            continue
        values.append(rel)
    if not values:
        return "_kc_preserve_paths='';"
    joined = " ".join(shlex.quote(value) for value in values)
    return f"_kc_preserve_paths={shlex.quote(joined)};"


def _join_shell(*parts: str) -> str:
    return " ".join(part.strip() for part in parts if part and part.strip())
