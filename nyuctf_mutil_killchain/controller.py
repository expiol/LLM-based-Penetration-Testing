"""Top-level run controller for assembling and executing a session."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nyuctf_mutil_killchain.agents import (
    ArchiveTriageAgent,
    ArtifactTriageAgent,
    BinaryTriageAgent,
    ComputationAnalysisAgent,
    FlagValidationAgent,
    HostAuditAgent,
    PcapReviewAgent,
    ReconAgent,
    RepoReviewAgent,
    RuntimeProbeAgent,
    ServiceBannerAgent,
    SourceReviewAgent,
    SQLiteReviewAgent,
    VulnScanAgent,
    WebAssessmentAgent,
    WebContentAgent,
    WebPathProbeAgent,
)
from nyuctf_mutil_killchain.llm import LLMClientError, build_llm_client_from_env
from nyuctf_mutil_killchain.orchestrator import HeuristicPlanner, LLMPlanner, Orchestrator
from nyuctf_mutil_killchain.reporting import render_markdown_report
from nyuctf_mutil_killchain.state import GlobalState
from nyuctf_mutil_killchain.tools import ExecutionPlane, build_execution_plane


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


class RunConfig(BaseModel):
    """Configuration for one local assessment run."""

    model_config = ConfigDict(extra="ignore")

    objective: str
    authorized_scope: list[str]
    output_root: str = "runs"
    max_cycles: int = Field(default=6, ge=1)
    enable_llm: bool = True
    enable_llm_planner: bool = True
    quiet: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "RunConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if "scope" in payload and "authorized_scope" not in payload:
            payload["authorized_scope"] = payload.pop("scope")
        return cls.model_validate(payload)


class RunArtifacts(BaseModel):
    """Filesystem outputs produced by a run."""

    run_id: str
    run_dir: str
    state_path: str
    summary_path: str
    report_path: str
    events_path: str
    config_path: str
    evidence_path: str
    status: str


class EventRecorder:
    """Collects orchestrator emit events and optionally echoes them to stdout."""

    def __init__(self, *, quiet: bool = False) -> None:
        self.quiet = quiet
        self.messages: list[str] = []

    def emit(self, message: str) -> None:
        self.messages.append(message)
        if not self.quiet:
            print(message)


def build_runtime(
    config: RunConfig,
    *,
    recorder: EventRecorder | None = None,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
) -> tuple[GlobalState, Orchestrator]:
    """Assemble state, planner, workers, and execution plane for one run."""

    llm_client = None
    if config.enable_llm:
        llm_client = build_llm_client_from_env()

    planner = HeuristicPlanner()
    if config.enable_llm_planner and llm_client is not None:
        planner = LLMPlanner(llm_client, fallback=planner)

    execution_plane = execution_plane or build_execution_plane()
    state = GlobalState(
        objective=config.objective,
        authorized_scope=config.authorized_scope,
        metadata=dict(config.metadata),
    )
    orchestrator = Orchestrator(
        state=state,
        workers=[
            ReconAgent(execution_plane=execution_plane),
            ArtifactTriageAgent(execution_plane=execution_plane),
            ArchiveTriageAgent(execution_plane=execution_plane),
            BinaryTriageAgent(execution_plane=execution_plane),
            ComputationAnalysisAgent(execution_plane=execution_plane),
            SQLiteReviewAgent(execution_plane=execution_plane),
            PcapReviewAgent(execution_plane=execution_plane),
            RepoReviewAgent(execution_plane=execution_plane),
            RuntimeProbeAgent(execution_plane=execution_plane),
            SourceReviewAgent(execution_plane=execution_plane),
            HostAuditAgent(execution_plane=execution_plane),
            ServiceBannerAgent(execution_plane=execution_plane),
            WebAssessmentAgent(llm_client=llm_client, execution_plane=execution_plane),
            WebContentAgent(llm_client=llm_client, execution_plane=execution_plane),
            WebPathProbeAgent(execution_plane=execution_plane),
            VulnScanAgent(execution_plane=execution_plane),
            FlagValidationAgent(expected_flag=expected_flag),
        ],
        planner=planner,
        emit=(recorder.emit if recorder is not None else print),
    )
    return state, orchestrator


def build_summary(state: GlobalState) -> dict[str, Any]:
    """Create a compact JSON summary for one run."""

    return {
        "run_id": state.run_id,
        "status": state.status,
        "solved": state.solved,
        "validated_flag": state.validated_flag,
        "objective": state.objective,
        "authorized_scope": state.authorized_scope,
        "assets": len(state.assets),
        "findings": len(state.findings),
        "evidence": len(state.evidence),
        "executions": len(state.execution_log),
    }


def run_assessment(
    config: RunConfig,
    *,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
) -> RunArtifacts:
    """Run the full local workflow and persist artifacts."""

    recorder = EventRecorder(quiet=config.quiet)
    state, orchestrator = build_runtime(
        config,
        recorder=recorder,
        execution_plane=execution_plane,
        expected_flag=expected_flag,
    )

    try:
        final_state = orchestrator.run(max_cycles=config.max_cycles)
    except LLMClientError:
        raise

    run_dir = Path(config.output_root) / final_state.run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    config_path = run_dir / "config.json"
    state_path = run_dir / "state.json"
    summary_path = run_dir / "summary.json"
    report_path = run_dir / "report.md"
    events_path = run_dir / "events.log"
    evidence_path = run_dir / "evidence.json"

    _write_json(config_path, config.model_dump(mode="json"))
    _write_json(state_path, final_state.model_dump(mode="json"))
    _write_json(summary_path, build_summary(final_state))
    _write_json(
        evidence_path,
        {
            "evidence": {
                key: value.model_dump(mode="json")
                for key, value in sorted(final_state.evidence.items(), key=lambda item: item[0])
            }
        },
    )
    report_path.write_text(render_markdown_report(final_state), encoding="utf-8")
    events_path.write_text("\n".join(recorder.messages) + ("\n" if recorder.messages else ""), encoding="utf-8")

    return RunArtifacts(
        run_id=final_state.run_id,
        run_dir=str(run_dir),
        state_path=str(state_path),
        summary_path=str(summary_path),
        report_path=str(report_path),
        events_path=str(events_path),
        config_path=str(config_path),
        evidence_path=str(evidence_path),
        status=final_state.status,
    )
