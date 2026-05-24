"""Self-test helpers for the NYU multi-killchain workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

from killchain_docker.controller import RunConfig, run_assessment
from killchain_docker.logging_utils import (
    configure_logging,
    write_json_file,
    write_json_stdout,
    write_jsonl_file,
)
from killchain_docker.llm import StaticLLMClient
from killchain_docker.score import (
    build_validation_payload,
    summarize_logdir,
    summarize_run_dir,
)
from killchain_docker.tools import (
    ExecutionMode,
    ExecutionPlane,
    ToolExecutionRequest,
    ToolExecutionResult,
    build_execution_plane,
)
from killchain_docker.tools.plugins.shell import build_output as shell_output_builder
from killchain_docker.tools.plugins.script import build_output as script_output_builder


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    write_json_file(path, payload)


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    write_jsonl_file(path, rows)


class SimulatedShellPlugin:
    """Simulated shell plugin for self-test — returns canned output based on command."""

    name = "shell_exec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, expected_flag: str) -> None:
        self._expected_flag = expected_flag

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        command = str(request.metadata.get("command") or "")

        # Simulate different shell commands based on content
        if "nmap" in command or "scan" in command:
            stdout = (
                "Starting Nmap 7.92\n"
                "PORT     STATE SERVICE\n"
                "8080/tcp open  http-proxy\n"
                "Nmap done: 1 IP address (1 host up)\n"
            )
        elif "curl" in command:
            stdout = (
                "<html><title>Selftest Control Panel</title>\n"
                "<body><a href='/admin'>Admin</a><a href='/debug'>Debug</a>\n"
                f"<!-- {self._expected_flag} -->\n"
                "</body></html>\n"
            )
        elif "file " in command or "ls " in command:
            stdout = "app.py: Python script, ASCII text\n"
        elif "strings" in command or "grep" in command or "flag" in command:
            stdout = f"{self._expected_flag}\n"
        else:
            stdout = "command completed\n"

        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=stdout,
        )


class SimulatedScriptPlugin:
    """Simulated script plugin for self-test — returns canned output."""

    name = "script_exec"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, expected_flag: str) -> None:
        self._expected_flag = expected_flag

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=f"Script output: {self._expected_flag}\n",
        )


def _required_plugin_names() -> set[str]:
    return {"shell_exec", "script_exec"}


def _build_selftest_plane(expected_flag: str) -> ExecutionPlane:
    plane = ExecutionPlane()
    plane.register(SimulatedShellPlugin(expected_flag), shell_output_builder)
    plane.register(SimulatedScriptPlugin(expected_flag), script_output_builder)
    return plane


def run_selftest(output_root: str | Path) -> dict[str, Any]:
    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    live_plane = build_execution_plane()
    missing_plugins = sorted(_required_plugin_names() - set(live_plane.plugins))
    if missing_plugins:
        raise AssertionError(f"build_execution_plane() is missing plugins: {missing_plugins}")

    expected_flag = "flag{selftest-ok}"
    simulated_plane = _build_selftest_plane(expected_flag)
    runtime_root = root / "runtime"

    def selftest_llm_response(system_prompt: str, user_prompt: str) -> dict[str, Any]:
        if "PlannerDecision" in system_prompt or "PlannerAgent" in system_prompt:
            snapshot = json.loads(user_prompt)
            flag_candidates = snapshot.get("flag_candidates") or []
            todos = snapshot.get("todos") or []
            completed_goals = {
                str(todo.get("goal") or "")
                for todo in todos
                if todo.get("status") == "completed"
            }
            pending_goals = {
                str(todo.get("goal") or "")
                for todo in todos
                if todo.get("status") in {"pending", "running"}
            }
            if flag_candidates and "Validate selftest flag candidate." not in completed_goals | pending_goals:
                return {
                    "summary": "Validate discovered selftest flag.",
                    "todos": [
                        {
                            "goal": "Validate selftest flag candidate.",
                            "priority": 99,
                            "context": {"candidate_flag": flag_candidates[-1]["value"]},
                            "success_criteria": ["Confirm the candidate against the expected flag."],
                            "constraints": ["Do not fabricate alternate flags."],
                            "dedupe_key": f"selftest:validate:{flag_candidates[-1]['value']}",
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            assets = snapshot.get("assets") or []
            if assets and "Fetch selftest web content." not in completed_goals | pending_goals:
                asset = assets[0]
                return {
                    "summary": "Fetch selftest web content via curl.",
                    "todos": [
                        {
                            "goal": "Fetch selftest web content.",
                            "priority": 90,
                            "context": {
                                "asset_id": asset["asset_id"],
                                "base_url": asset["base_url"],
                            },
                            "success_criteria": ["Fetch content and surface flag candidates."],
                            "constraints": ["Stay on the known selftest base URL."],
                            "dedupe_key": "selftest:web-content",
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            return {
                "summary": "Selftest planner has no extra todo.",
                "todos": [],
                "notes": [],
                "stop_run": False,
            }

        if "RouterDecision" in system_prompt:
            snapshot = json.loads(user_prompt)
            ready = snapshot.get("ready_todos") or []
            assignments = []
            for todo in ready:
                goal = str(todo.get("goal") or "").lower()
                context = todo.get("context") or {}
                if todo.get("phase") == "flag_validation" or context.get("candidate_flag"):
                    worker_name = "flag-worker"
                elif context.get("base_url") or "web" in goal:
                    worker_name = "web-worker"
                elif context.get("scope") or "scope" in goal:
                    worker_name = "recon-worker"
                else:
                    worker_name = "artifact-worker"
                assignments.append(
                    {
                        "todo_id": todo["todo_id"],
                        "worker_name": worker_name,
                        "rationale": "selftest deterministic LLM route",
                    }
                )
            return {"assignments": assignments, "rationale": "selftest route"}

        if "RouterRoundSummary" in system_prompt:
            return {
                "summary": "Selftest router summary.",
                "direct_results": [],
                "key_findings": [],
                "next_focus": "",
                "used_llm": True,
            }

        # ToolUseDecision — worker selects a capability
        snapshot = json.loads(user_prompt)
        todo = snapshot.get("todo") or {}
        goal = str(todo.get("goal") or "").lower()
        context = todo.get("context") or {}

        # Recon uses shell.exec with nmap/curl; web uses shell.exec with curl;
        # artifact uses shell.exec with file/strings; default to shell.exec
        if context.get("scope") or "scope" in goal:
            command = f"nmap -sV -p- {context.get('scope', '127.0.0.1')}"
        elif context.get("base_url") or "web" in goal or "content" in goal:
            command = f"curl -s {context.get('base_url', 'http://127.0.0.1:8080')}"
        elif "flag" in goal or "harvest" in goal:
            command = "grep -r 'flag{' /home/ctfplayer/ctf_files/ 2>/dev/null || echo 'no flags found'"
        else:
            command = "file /home/ctfplayer/ctf_files/* 2>/dev/null"

        return {
            "capability": "shell.exec",
            "metadata": {"command": command},
            "rationale": "selftest selected shell.exec capability",
            "expected_signal": "selftest tool result",
            "hypothesis": None,
            "memory_updates": {},
        }

    selftest_llm = StaticLLMClient(selftest_llm_response)

    config = RunConfig(
        objective="Self-test the NYU multi-killchain orchestrator without docker.",
        authorized_scope=["http://127.0.0.1:8080"],
        output_root=str(runtime_root / "runs"),
        max_cycles=8,
        quiet=True,
        metadata={
            "challenge": {
                "canonical_name": "selftest-web",
                "name": "selftest-web",
                "category": "web",
                "files": ["app.py"],
            }
        },
    )
    artifacts = run_assessment(
        config,
        execution_plane=simulated_plane,
        expected_flag=expected_flag,
        llm_client=selftest_llm,
    )

    summary_path = Path(artifacts.summary_path)
    state_path = Path(artifacts.state_path)
    events_path = Path(artifacts.events_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    if not summary.get("solved"):
        raise AssertionError("selftest runtime did not reach solved state")
    if summary.get("validated_flag") != expected_flag:
        raise AssertionError("selftest runtime did not preserve validated flag in summary")
    if artifacts.status != "solved":
        raise AssertionError(f"unexpected selftest run status: {artifacts.status}")
    if not any(event.get("event_type") == "solved" for event in events):
        raise AssertionError("events log does not show solved state")

    score_root = root / "score"
    run_dir = score_root / "batch_run"
    logdir = score_root / "logs"
    run_dir.mkdir(parents=True, exist_ok=True)
    logdir.mkdir(parents=True, exist_ok=True)

    batch_record = {
        "index": 1,
        "challenge": "selftest-web",
        "status": "solved",
        "returncode": 0,
        "solved": True,
        "validated_flag": expected_flag,
        "run_dir": artifacts.run_dir,
        "summary_file": artifacts.summary_path,
        "report_file": artifacts.report_path,
        "logfile": str(logdir / "selftest-web.json"),
    }
    _write_jsonl(run_dir / "results.jsonl", [batch_record])

    log_payload = {
        "challenge_metadata": {"canonical_name": "selftest-web"},
        "solved": True,
        "status": "solved",
        "finish_reason": "solved",
        "state": {"validated_flag": expected_flag},
        "summary": {"validated_flag": expected_flag},
    }
    _write_json(logdir / "selftest-web.json", log_payload)

    run_dir_results = summarize_run_dir(run_dir)
    run_dir_validation = build_validation_payload(
        results=run_dir_results,
        expected_challenges=["selftest-web"],
        split="development",
    )
    if run_dir_validation["score"]["solved"] != 1:
        raise AssertionError("run-dir score validation did not count the solved challenge")
    if run_dir_validation["coverage"]["missing"]:
        raise AssertionError("run-dir score validation reported missing challenges unexpectedly")

    logdir_results = summarize_logdir(logdir)
    logdir_validation = build_validation_payload(
        results=logdir_results,
        expected_challenges=["selftest-web"],
        split="development",
    )
    if logdir_validation["score"]["solved"] != 1:
        raise AssertionError("logdir score validation did not count the solved challenge")
    if logdir_validation["coverage"]["missing"]:
        raise AssertionError("logdir score validation reported missing challenges unexpectedly")

    payload = {
        "ok": True,
        "checks": {
            "plugin_registry": {
                "required_plugins": sorted(_required_plugin_names()),
                "registered_plugins": sorted(live_plane.plugins),
            },
            "runtime": {
                "status": artifacts.status,
                "run_dir": artifacts.run_dir,
                "summary_path": artifacts.summary_path,
                "report_path": artifacts.report_path,
                "state_path": artifacts.state_path,
                "summary": summary,
                "todo_count": len(state.get("todos", [])),
                "execution_count": len(state.get("execution_log", [])),
            },
            "score_run_dir": run_dir_validation["score"],
            "score_logdir": logdir_validation["score"],
        },
    }
    _write_json(root / "selftest_report.json", payload)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local self-test for the killchain workflow (no Docker)")
    parser.add_argument(
        "--output-root",
        default="selftest_output",
        help="Directory where self-test artifacts are written",
    )
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    configure_logging(debug=args.debug, quiet=args.quiet)

    payload = run_selftest(args.output_root)
    write_json_stdout(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
