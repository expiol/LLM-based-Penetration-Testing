"""Top-level run controller for assembling and executing a session."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from nyuctf_mutil_killchain.agents import (
    ArchiveTriageAgent,
    ArtifactTriageAgent,
    BinaryTriageAgent,
    ComputationAnalysisAgent,
    CredentialExploitAgent,
    CredentialHuntAgent,
    DeepReviewAgent,
    ExploitReasoningAgent,
    FlagHuntAgent,
    FlagValidationAgent,
    HostAuditAgent,
    PcapReviewAgent,
    ReconAgent,
    RepoReviewAgent,
    RuntimeProbeAgent,
    ServiceBannerAgent,
    SolverAgent,
    SourceReviewAgent,
    SqliteReviewAgent,
    VulnScanAgent,
    WebAssessmentAgent,
    WebContentAgent,
    WebFormProbeAgent,
    WebPathProbeAgent,
    WebPwnExploitAgent,
)
from nyuctf_mutil_killchain.knowledge import KnowledgeAugmenter
from nyuctf_mutil_killchain.llm import LLMClient, TokenLedger, build_llm_client_from_env
from nyuctf_mutil_killchain.orchestrator import (
    LLMPlanner,
    LLMWorkerRouter,
    Orchestrator,
)
from nyuctf_mutil_killchain.reporting import render_markdown_report
from nyuctf_mutil_killchain.state import GlobalState
from nyuctf_mutil_killchain.tools import ExecutionPlane, build_execution_plane


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")


class RunPersister:
    """Owns disk paths for one run and writes them lazily.

    ``write_state`` is the cheap checkpoint (state.json + events.log) called
    after every orchestrator cycle so a crash never wipes mid-run progress.
    ``write_all`` is the full snapshot called from controller.run_assessment's
    ``finally`` block to guarantee state/summary/report/evidence/events all
    land on disk regardless of whether ``orchestrator.run`` raised.
    """

    def __init__(self, run_dir: Path, recorder: EventRecorder) -> None:
        self.run_dir = run_dir
        self.recorder = recorder
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = run_dir / "config.json"
        self.state_path = run_dir / "state.json"
        self.summary_path = run_dir / "summary.json"
        self.report_path = run_dir / "report.md"
        self.events_path = run_dir / "events.log"
        self.evidence_path = run_dir / "evidence.json"

    def write_config(self, config: RunConfig) -> None:
        _write_json(self.config_path, config.model_dump(mode="json"))

    def _write_events(self) -> None:
        messages = list(self.recorder.messages)
        suffix = "\n" if messages else ""
        self.events_path.write_text("\n".join(messages) + suffix, encoding="utf-8")

    def write_state(self, state: GlobalState) -> None:
        try:
            _write_json(self.state_path, state.model_dump(mode="json"))
            self._write_events()
        except Exception as exc:
            self.recorder.emit(
                f"[persister] checkpoint write failed: {type(exc).__name__}: {exc}"
            )

    def write_all(
        self,
        state: GlobalState,
        token_ledger: TokenLedger | None,
    ) -> None:
        _write_json(self.state_path, state.model_dump(mode="json"))
        _write_json(self.summary_path, build_summary(state, token_ledger))
        _write_json(
            self.evidence_path,
            {
                "evidence": {
                    key: value.model_dump(mode="json")
                    for key, value in sorted(state.evidence.items(), key=lambda item: item[0])
                }
            },
        )
        self.report_path.write_text(render_markdown_report(state), encoding="utf-8")
        self._write_events()


class RunConfig(BaseModel):
    """Configuration for one local assessment run."""

    model_config = ConfigDict(extra="ignore")

    objective: str
    authorized_scope: list[str]
    output_root: str = "runs"
    max_cycles: int = Field(default=8, ge=1)
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
    llm_client: LLMClient | None = None,
    checkpoint_callback: Callable[[GlobalState], None] | None = None,
) -> tuple[GlobalState, Orchestrator, LLMClient]:
    """Assemble state, planner, workers, and execution plane for one run."""

    if llm_client is None:
        llm_client = build_llm_client_from_env()

    # One augmenter per run, shared by planner + solver + dispatch policy.
    # ``from_default`` resolves to the module-level retriever singleton
    # (or ``None`` when fastembed / the dataset isn't available), so the
    # caller never has to know whether RAG is wired up.
    augmenter = KnowledgeAugmenter.from_default()

    planner = LLMPlanner(llm_client, augmenter=augmenter)
    router = LLMWorkerRouter(llm_client)

    execution_plane = execution_plane or build_execution_plane()
    state = GlobalState(
        objective=config.objective,
        authorized_scope=config.authorized_scope,
        metadata=dict(config.metadata),
    )
    common = {"llm_client": llm_client, "execution_plane": execution_plane}
    orchestrator = Orchestrator(
        state=state,
        workers=[
            # Recon / host
            ReconAgent(**common),
            HostAuditAgent(**common),
            ServiceBannerAgent(**common),
            # Artifact / static analysis
            ArtifactTriageAgent(**common),
            BinaryTriageAgent(**common),
            ArchiveTriageAgent(**common),
            SqliteReviewAgent(**common),
            PcapReviewAgent(**common),
            RepoReviewAgent(**common),
            SourceReviewAgent(**common),
            ComputationAnalysisAgent(**common),
            RuntimeProbeAgent(**common),
            DeepReviewAgent(**common),
            # Web
            WebAssessmentAgent(**common),
            WebContentAgent(**common),
            WebFormProbeAgent(**common),
            WebPathProbeAgent(**common),
            # Vuln
            VulnScanAgent(**common),
            # Credential / exploit
            CredentialHuntAgent(**common),
            CredentialExploitAgent(**common),
            WebPwnExploitAgent(**common),
            ExploitReasoningAgent(**common),
            FlagHuntAgent(**common),
            # Solver (gets the augmenter so its prompts include writeup hits).
            SolverAgent(augmenter=augmenter, **common),
            # Flag validation (no execution_plane needed)
            FlagValidationAgent(llm_client=llm_client, expected_flag=expected_flag),
        ],
        planner=planner,
        router=router,
        emit=(recorder.emit if recorder is not None else print),
        checkpoint_callback=checkpoint_callback,
        augmenter=augmenter,
    )
    return state, orchestrator, llm_client


def build_summary(state: GlobalState, token_ledger: TokenLedger | None = None) -> dict[str, Any]:
    """Create a compact JSON summary for one run."""

    summary: dict[str, Any] = {
        "run_id": state.run_id,
        "status": state.status,
        "solved": state.solved,
        "validated_flag": state.validated_flag,
        "objective": state.objective,
        "authorized_scope": state.authorized_scope,
        "assets": len(state.assets),
        "findings": len(state.findings),
        "credentials": len(state.credentials),
        "evidence": len(state.evidence),
        "executions": len(state.execution_log),
    }
    if token_ledger is not None:
        summary["token_usage"] = token_ledger.to_dict()
    return summary


def run_assessment(
    config: RunConfig,
    *,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
    llm_client: LLMClient | None = None,
) -> RunArtifacts:
    """Run the full local workflow and persist artifacts.

    Persistence is wrapped in ``try/finally`` so that state/summary/report/
    evidence/events are always written, even if ``orchestrator.run`` raises.
    """

    recorder = EventRecorder(quiet=config.quiet)
    state, orchestrator, active_llm_client = build_runtime(
        config,
        recorder=recorder,
        execution_plane=execution_plane,
        expected_flag=expected_flag,
        llm_client=llm_client,
    )
    run_dir = Path(config.output_root) / state.run_id
    persister = RunPersister(run_dir, recorder)
    persister.write_config(config)
    orchestrator.checkpoint_callback = persister.write_state

    token_ledger = getattr(active_llm_client, "token_ledger", None)

    try:
        orchestrator.run(max_cycles=config.max_cycles)
    finally:
        if token_ledger is not None:
            recorder.emit(
                f"[token usage] calls={token_ledger.llm_calls} "
                f"prompt={token_ledger.prompt_tokens} "
                f"completion={token_ledger.completion_tokens} "
                f"total={token_ledger.total_tokens}"
            )
        persister.write_all(state, token_ledger)

    return RunArtifacts(
        run_id=state.run_id,
        run_dir=str(run_dir),
        state_path=str(persister.state_path),
        summary_path=str(persister.summary_path),
        report_path=str(persister.report_path),
        events_path=str(persister.events_path),
        config_path=str(persister.config_path),
        evidence_path=str(persister.evidence_path),
        status=state.status,
    )
