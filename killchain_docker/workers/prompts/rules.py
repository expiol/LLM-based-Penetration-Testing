"""Worker tool-use rules and system prompt reminders."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability


def tool_use_rules(allowed: set[ToolCapability]) -> list[str]:
    rules = [
        "Choose exactly one capability from tool_catalog.",
        "Use recent_evidence_context before repeating diagnostics already present there.",
    ]
    if ToolCapability.SHELL_EXEC in allowed:
        rules.extend(
            [
                "For shell.exec, put the full command string in 'command'. Use installed tools only; if a dependency is missing, record that fact and choose another available route.",
                "Do not use shell.exec for complex Python one-liners. If Python needs with/if/for/while, file parsing, or multi-line logic, choose script.exec instead.",
                "Do not use shell.exec for package installation or updates (apt, yum, dnf, apk, pacman, brew, pip, npm, yarn, gem, cargo, go).",
                "Prefer shell.exec for bounded inspection, installed-tool diagnostics, and simple authorized network probes.",
                "Keep file searches under files_root or explicit challenge paths from todo context/evidence.",
                "Any shell.exec writes under files_root are discarded after the command. Use CTF_TEMP_DIR instead of /tmp for scratch files; direct /tmp references are blocked. CTF_ORIGINAL_FILES_ROOT is a separate pristine snapshot for comparing file sizes/hashes during one command; read from it, never write to it.",
            ]
        )
    if ToolCapability.SCRIPT_EXEC in allowed:
        rules.extend(
            [
                "For script.exec, provide complete self-contained script_code and print diagnostics/results to stdout.",
                "Do not assume third-party Python packages are installed (z3, rstr, exrex, pwntools, requests, Crypto, numpy, etc.). Prefer stdlib. If you use an optional import, catch ImportError and include a stdlib fallback in the same script; never spend a run step installing packages.",
                "Keep generated scripts syntactically simple: put control flow in functions and call main() under if __name__ == '__main__'. Do not use return outside a function, break/continue outside a loop, or top-level fragments that cannot pass ast.parse.",
                "script.exec starts in a disposable copy of files_root; use relative paths or CTF_FILES_ROOT for challenge files and generated artifacts. Use CTF_TEMP_DIR or tempfile for scratch files. Do not write to /tmp, /home outside CTF_FILES_ROOT, or CTF_ORIGINAL_FILES_ROOT. Do not manually os.rmdir()/rmdir CTF_TEMP_DIR or tempfile.mkdtemp() directories after writing files there; the runner cleans disposable scratch, and generated scratch artifacts are published before cleanup.",
                "CTF_ORIGINAL_FILES_ROOT is a separate pristine snapshot for checking original sizes/hashes while the disposable work copy is being modified.",
                "Prefer script.exec for multi-step logic, parsing, computation, and bounded local diagnostics.",
                "Every script.exec script must terminate within its timeout by design: bound loops, cap brute-force/search variants, set socket/subprocess timeouts, and avoid package installation.",
                "For network or protocol scripts, prefer Python stdlib modules (socket, ssl, http.client, urllib, telnetlib where available). Set connect/read socket timeouts <=5 seconds and keep the overall script deadline <=45 seconds. Do not switch to localhost/127.0.0.1 unless that endpoint is explicitly in authorized_scope.",
                "Challenge files are copied from /home/ctfplayer/ctf_files by default.",
            ]
        )
    return rules


def script_reminder(allowed: set[ToolCapability]) -> str:
    if ToolCapability.SCRIPT_EXEC not in allowed:
        return ""
    return "CRITICAL: For script.exec, 'script_code' is MANDATORY and must contain the COMPLETE executable source code as a string - not a description of what to write, but the actual runnable Python/bash code. Generated scripts MUST be bounded: no unbounded brute force, no per-step loops over huge counters, no network waits without socket timeouts, and no package installation. Prefer Python stdlib. If an optional third-party import is useful, catch ImportError and include a stdlib fallback in the same script. "


def shell_reminder(allowed: set[ToolCapability]) -> str:
    if ToolCapability.SHELL_EXEC not in allowed:
        return ""
    return "For shell.exec, 'command' is MANDATORY and must contain the full shell command to execute via bash -c. You can use any tool installed in the container: curl, nmap, sqlmap, strings, file, binwalk, r2, tshark, etc. Use curl/wget only for HTTP/HTTPS; for tcp:// or custom services choose script.exec with Python sockets and explicit timeouts. Do not embed complex Python in python -c; if Python needs with/if/for/while, file parsing, or multi-line logic, choose script.exec instead. Do not run apt/yum/apk/pip/npm installs or package-manager updates; if a tool is missing, record that fact and pivot to installed tools. Shell commands run with challenge-file snapshot protection; any writes under files_root are discarded after execution, so print evidence to stdout. Use CTF_TEMP_DIR for scratch files; it is deleted after the tool call. CTF_ORIGINAL_FILES_ROOT points to a separate pristine snapshot for comparing sizes/hashes during the same command; read from it, but never write to it. When running a challenge binary or tool that may derive an output path from the input path, copy the input to CTF_TEMP_DIR with a non-colliding name first and verify the output path is not the same as the input. "
