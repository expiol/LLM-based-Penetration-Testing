"""Self-test helpers for the NYU multi-killchain workflow."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable, Sequence

from nyuctf_mutil_killchain.controller import RunConfig, run_assessment
from nyuctf_mutil_killchain.score import (
    build_validation_payload,
    summarize_logdir,
    summarize_run_dir,
)
from nyuctf_mutil_killchain.tools import (
    ExecutionMode,
    ExecutionPlane,
    ToolExecutionRequest,
    ToolExecutionResult,
    build_execution_plane,
    jsonl_signal_parser,
)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "".join(json.dumps(row, ensure_ascii=True) + "\n" for row in rows)
    path.write_text(content, encoding="utf-8")


def _jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(record, ensure_ascii=True) + "\n" for record in records)


class SimulatedJsonlPlugin:
    """Simple in-process plugin used by the self-test execution plane."""

    mode = ExecutionMode.SIMULATED

    def __init__(
        self,
        *,
        name: str,
        emit_records: Callable[[ToolExecutionRequest], list[dict[str, Any]]],
    ) -> None:
        self.name = name
        self._emit_records = emit_records

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=_jsonl(self._emit_records(request)),
        )


def _required_plugin_names() -> set[str]:
    return {
        "artifact_triage",
        "archive_triage",
        "binary_triage",
        "http_path_probe",
        "local_host_inventory",
        "local_http_content",
        "local_http_metadata",
        "pcap_review",
        "repo_review",
        "sqlite_review",
        "source_review",
        "tcp_banner_probe",
        "vuln_scan",
    }


def _build_selftest_plane(expected_flag: str) -> ExecutionPlane:
    plane = ExecutionPlane()
    plane.register_parser("jsonl_signals", jsonl_signal_parser)

    def emit_http_metadata(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        asset_id = str(request.metadata.get("asset_id") or "seed-asset")
        base_url = str(request.metadata.get("base_url") or "http://127.0.0.1:8080")
        return [
            {"type": "summary", "text": f"Collected HTTP metadata for {base_url}."},
            {
                "type": "asset",
                "asset_id": asset_id,
                "kind": "web_application",
                "hostname": "127.0.0.1",
                "ip_address": "127.0.0.1",
                "base_url": base_url,
                "tags": ["observed", "selftest"],
                "services": [
                    {
                        "port": 8080,
                        "protocol": "tcp",
                        "name": "http",
                        "product": "selftest-httpd/1.0",
                        "version": "1.0",
                    }
                ],
                "metadata": {"source": "selftest-http-metadata"},
            },
            {
                "type": "output_context",
                "http_status": 200,
                "server": "selftest-httpd/1.0",
                "powered_by": "selftest-app",
                "security_issues": ["Missing Content-Security-Policy header"],
                "base_url": base_url,
            },
        ]

    def emit_http_content(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        asset_id = str(request.metadata.get("asset_id") or "seed-asset")
        base_url = str(request.metadata.get("base_url") or "http://127.0.0.1:8080")
        return [
            {"type": "summary", "text": f"Reviewed HTTP content for {base_url}."},
            {
                "type": "output_context",
                "title": "Selftest Control Panel",
                "interesting_links": ["/admin", "/debug"],
                "forms": [{"action": "/login", "method": "post"}],
                "keywords": ["admin", "login", "debug"],
                "potential_flags": [expected_flag],
            },
            {
                "type": "finding",
                "finding_id": f"finding-{asset_id}-selftest-content",
                "title": "Selftest content review evidence",
                "severity": "medium",
                "description": "Simulated content review exposed administrative surface.",
                "asset_refs": [asset_id],
                "evidence_refs": [base_url, expected_flag],
                "metadata": {"source": "selftest-http-content"},
            },
        ]

    def emit_artifact_triage(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        files_root = str(request.metadata.get("files_root") or "/home/ctfplayer/ctf_files")
        return [
            {"type": "summary", "text": "Inventoried challenge files."},
            {
                "type": "output_context",
                "files_root": files_root,
                "binary_files": [],
                "web_source_files": ["app.py"],
                "flag_candidates": [],
                "file_count": 1,
            },
            {
                "type": "finding",
                "finding_id": "finding-selftest-artifacts",
                "title": "Challenge files inventoried",
                "severity": "info",
                "description": "Self-test discovered one source file for follow-up review.",
                "asset_refs": ["challenge"],
                "evidence_refs": ["app.py"],
                "metadata": {"source": "selftest-artifact-triage"},
            },
        ]

    def emit_source_review(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_files = list(request.metadata.get("source_files") or ["app.py"])
        return [
            {"type": "summary", "text": "Reviewed source artifacts."},
            {
                "type": "output_context",
                "inspected_files": inspected_files,
                "interesting_routes": ["/admin"],
                "secret_files": ["app.py"],
                "flag_candidates": [],
            },
            {
                "type": "finding",
                "finding_id": "finding-selftest-source-review",
                "title": "Source review found admin route",
                "severity": "medium",
                "description": "Simulated source review identified an /admin route and a secret-bearing file.",
                "asset_refs": ["challenge"],
                "evidence_refs": inspected_files,
                "metadata": {"source": "selftest-source-review"},
            },
        ]

    def emit_binary_triage(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_files = list(request.metadata.get("binary_files") or [])
        return [
            {"type": "summary", "text": "Binary triage completed with no flag candidates."},
            {
                "type": "output_context",
                "inspected_files": inspected_files,
                "flag_candidates": [],
            },
        ]

    def emit_archive_triage(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_files = list(request.metadata.get("archive_files") or [])
        return [
            {"type": "summary", "text": "Archive triage completed with no flag candidates."},
            {
                "type": "output_context",
                "inspected_archives": inspected_files,
                "flag_candidates": [],
            },
        ]

    def emit_sqlite_review(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_files = list(request.metadata.get("database_files") or [])
        return [
            {"type": "summary", "text": "SQLite review completed with no flag candidates."},
            {
                "type": "output_context",
                "inspected_databases": inspected_files,
                "tables": {},
                "flag_candidates": [],
            },
        ]

    def emit_pcap_review(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_files = list(request.metadata.get("pcap_files") or [])
        return [
            {"type": "summary", "text": "PCAP review completed with no flag candidates."},
            {
                "type": "output_context",
                "inspected_pcaps": inspected_files,
                "urls": [],
                "hosts": [],
                "flag_candidates": [],
            },
        ]

    def emit_repo_review(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        inspected_repos = list(request.metadata.get("repo_paths") or [])
        return [
            {"type": "summary", "text": "Repository review completed with no flag candidates."},
            {
                "type": "output_context",
                "inspected_repos": inspected_repos,
                "commit_summaries": {},
                "flag_candidates": [],
            },
        ]

    def emit_host_inventory(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        asset_id = str(request.metadata.get("asset_id") or "selftest-host")
        hostname = str(request.metadata.get("hostname") or "127.0.0.1")
        return [
            {"type": "summary", "text": f"Host inventory completed for {hostname}."},
            {
                "type": "asset",
                "asset_id": asset_id,
                "kind": "host",
                "hostname": hostname,
                "ip_address": "127.0.0.1",
                "tags": ["selftest", "host"],
                "services": [{"port": 8080, "protocol": "tcp", "name": "http"}],
                "metadata": {"source": "selftest-host-inventory"},
            },
            {"type": "output_context", "scan_method": "selftest", "ports": [8080]},
        ]

    def emit_tcp_banner(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        hostname = str(request.metadata.get("hostname") or "127.0.0.1")
        return [
            {"type": "summary", "text": f"TCP banner probe completed for {hostname}."},
            {
                "type": "output_context",
                "hostname": hostname,
                "responsive_ports": [8080],
                "banner_hits": {"8080": "selftest banner"},
                "flag_candidates": [],
            },
        ]

    def emit_http_path_probe(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        base_url = str(request.metadata.get("base_url") or "http://127.0.0.1:8080")
        paths = list(request.metadata.get("paths") or [])
        interesting_paths = [f"{base_url.rstrip('/')}/{path.lstrip('/')}" for path in paths[:3]]
        return [
            {"type": "summary", "text": f"HTTP path probe completed for {base_url}."},
            {
                "type": "output_context",
                "base_url": base_url,
                "path_results": [{"url": url, "status": 200, "title": "Selftest"} for url in interesting_paths],
                "interesting_paths": interesting_paths,
                "flag_candidates": [],
            },
        ]

    def emit_vuln_scan(request: ToolExecutionRequest) -> list[dict[str, Any]]:
        target = str(request.metadata.get("target") or request.metadata.get("base_url") or "unknown")
        return [
            {"type": "summary", "text": f"Simulated vuln scan completed for {target}."},
            {"type": "output_context", "scan_method": "selftest", "vuln_count": 0},
        ]

    plane.register_plugin(
        SimulatedJsonlPlugin(name="local_http_metadata", emit_records=emit_http_metadata)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="local_http_content", emit_records=emit_http_content)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="artifact_triage", emit_records=emit_artifact_triage)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="archive_triage", emit_records=emit_archive_triage)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="source_review", emit_records=emit_source_review)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="binary_triage", emit_records=emit_binary_triage)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="sqlite_review", emit_records=emit_sqlite_review)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="pcap_review", emit_records=emit_pcap_review)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="repo_review", emit_records=emit_repo_review)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="local_host_inventory", emit_records=emit_host_inventory)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="tcp_banner_probe", emit_records=emit_tcp_banner)
    )
    plane.register_plugin(
        SimulatedJsonlPlugin(name="http_path_probe", emit_records=emit_http_path_probe)
    )
    plane.register_plugin(SimulatedJsonlPlugin(name="vuln_scan", emit_records=emit_vuln_scan))
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
    config = RunConfig(
        objective="Self-test the NYU multi-killchain orchestrator without docker.",
        authorized_scope=["http://127.0.0.1:8080"],
        output_root=str(runtime_root / "runs"),
        max_cycles=8,
        enable_llm=False,
        enable_llm_planner=False,
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
    )

    summary_path = Path(artifacts.summary_path)
    state_path = Path(artifacts.state_path)
    events_path = Path(artifacts.events_path)
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    state = json.loads(state_path.read_text(encoding="utf-8"))
    events = events_path.read_text(encoding="utf-8")

    if not summary.get("solved"):
        raise AssertionError("selftest runtime did not reach solved state")
    if summary.get("validated_flag") != expected_flag:
        raise AssertionError("selftest runtime did not preserve validated flag in summary")
    if artifacts.status != "solved":
        raise AssertionError(f"unexpected selftest run status: {artifacts.status}")
    if "solved" not in events:
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
                "task_count": len(state.get("task_chain", {}).get("tasks", [])),
                "execution_count": len(state.get("execution_log", [])),
            },
            "score_run_dir": run_dir_validation["score"],
            "score_logdir": logdir_validation["score"],
        },
    }
    _write_json(root / "selftest_report.json", payload)
    return payload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a local self-test for the NYU multi-killchain workflow")
    parser.add_argument(
        "--output-root",
        default="selftest_mutil_killchain",
        help="Directory where self-test artifacts are written",
    )
    args = parser.parse_args(argv)

    payload = run_selftest(args.output_root)
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
