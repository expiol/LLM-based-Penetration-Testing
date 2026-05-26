"""Repair instructions for failed shell and script tool attempts."""

from __future__ import annotations


def shell_correction_instruction(failure_kind: object) -> str:
    instruction = "The previous shell command failed. Analyze stderr/stdout and do not repeat the same command. If the command embedded Python with python -c and hit SyntaxError or needed with/if/for/while or file parsing, choose script.exec and provide complete multi-line script_code instead."
    if failure_kind == "unbounded_extraction_blocked":
        return "The previous shell command was blocked because it attempted unbounded extraction. Do not repeat raw binwalk -e or dd bs=1 skip without count. Use the binwalk capability with extract=true/max_extract_mb, or choose script.exec and do bounded Python seek/read using known offsets, archive EOF/EOCD, or a strict byte count."
    if failure_kind == "non_http_url_blocked":
        return "The previous shell command used curl/wget for a non-HTTP endpoint. Do not retry curl, wget, or shell failure masking such as `|| echo`. For tcp:// or custom services, choose script.exec and write a small stdlib socket harness with connect/read timeouts <=5 seconds, an overall deadline <=45 seconds, explicit send/receive framing, and concise diagnostics."
    if failure_kind == "stderr_suppression_blocked":
        return "The previous shell command hid stderr, which prevents reliable repair. Re-run a smaller diagnostic command with stderr visible or redirect stderr to stdout using 2>&1. Do not use 2>/dev/null, &>/dev/null, or failure masking while checking whether a tool, path, offset, archive, or filesystem operation works."
    if failure_kind == "missing_tool":
        return "The previous shell command called a tool that is not installed. Do not keep the missing command at the front of an && chain. Probe optional tools with command -v or separate commands, then pivot to installed equivalents, dedicated capabilities, or script.exec with stdlib parsing. Preserve stdout/stderr so the next step knows exactly which fallback worked."
    return instruction


def script_correction_instruction(failure_kind: object) -> str:
    base = "The previous script attempt failed or produced no flag. Use last_traceback, last_stderr, last_stdout, and failure_kind as raw execution feedback. Write a corrected, complete script and print the resulting diagnostics/results to stdout. "
    failure = str(failure_kind or "")
    if failure in {
        "connection_refused",
        "connection_reset",
        "network_incomplete_read",
        "network_pipe_closed",
    }:
        return (
            base
            + "Correct the script around the observed connection failure without leaving the authorized scope."
        )
    if failure == "host_resolution_error":
        return (
            base
            + "Correct URL handling before changing the exploit logic: parse any base URL into scheme, hostname, port, and path, pass only the hostname to socket/http client constructors, and keep requests inside authorized_scope."
        )
    if failure in {"timeout", "unbounded_loop_guard"}:
        return (
            base
            + "Correct the implementation so it terminates within the tool timeout and preserves useful output if it cannot complete."
        )
    if failure == "syntax_error":
        return base + "Correct the syntax before changing the underlying approach."
    if failure == "bytes_text_mismatch":
        return (
            base
            + "Use the traceback line to identify the incompatible values and convert types deliberately at that boundary."
        )
    if failure == "path_type_mismatch":
        return (
            base
            + "Use the traceback line to identify the incompatible path values and convert types deliberately at that boundary."
        )
    if failure == "path_resolution_error":
        return (
            base
            + "Use the traceback line to identify the missing path. Recompute paths from CTF_FILES_ROOT, task metadata, generated artifact paths, or the current working directory, and verify existence before opening files."
        )
    if failure == "undefined_name":
        return (
            base
            + "Bind missing names from current task context, prior output, or values computed earlier in the same script."
        )
    if failure == "type_error":
        return (
            base
            + "Use the traceback line to identify the incompatible operation and inspect the involved values before converting them."
        )
    if failure == "no_candidate":
        return (
            base
            + "Use the previous stdout as evidence and correct the script's result extraction or reporting."
        )
    if failure == "near_miss":
        return (
            base
            + "Use the previous stdout as evidence and correct the incomplete extraction path."
        )
    if failure == "parse_error":
        return base + "Use the observed raw output to correct the input/output parser."
    if failure == "binary_structure_error":
        return (
            base
            + "Use the traceback line and observed lengths to add bounds checks before parsing structured data."
        )
    if failure == "scope_violation_blocked":
        return (
            base
            + "Remove the scope violation before changing the algorithm. For script.exec, set root = Path(os.environ.get('CTF_FILES_ROOT', '.')).resolve() and read or write only relative paths under that root. Use CTF_TEMP_DIR or tempfile for scratch files; do not hard-code /tmp. Do not scan /home, /root, /etc, /var, /opt, or shell startup files. If you need to inspect recovered data, inspect bytes already held in memory or files generated under CTF_FILES_ROOT in the same tool call."
        )
    if failure == "scratch_space_exhausted":
        return (
            base
            + "Correct scratch file usage so temporary files stay within the tool's provided writable locations and the script preserves concise diagnostics."
        )
    return base
