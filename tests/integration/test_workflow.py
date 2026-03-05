from pathlib import Path

from autopentest.core.config import load_config
from autopentest.core.logging import EventSink, configure_logging
from autopentest.graph.workflow import build_workflow
from autopentest.memory.evidence_store import EvidenceStore
from autopentest.orchestrator.budget import Budget
from autopentest.orchestrator.context import AgentContext
from autopentest.schemas.messages import SessionStatus, Scope, Target
from autopentest.tools.builtins import register_builtin_tools
from autopentest.tools.registry import ToolRegistry
from autopentest.tools.runner import ToolRunner
from autopentest.utils.time import utc_now


def test_workflow_runs_without_targets(tmp_path: Path) -> None:
    config = load_config(Path("configs/default.yaml"))
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    logger = configure_logging(config.logging.level, run_dir / "logs.jsonl")
    event_sink = EventSink(run_dir / "events.jsonl")
    evidence_store = EvidenceStore(run_dir)
    budget = Budget(config.budget.max_tool_calls, config.budget.max_runtime_seconds)
    registry = ToolRegistry()
    register_builtin_tools(registry)
    tool_runner = ToolRunner(registry, evidence_store, event_sink, budget, config, logger)

    target = Target(name="empty", hosts=[], ports=[], urls=[])
    scope = Scope(name="empty", allowed_hosts=[], allowed_networks=[], allowed_urls=[])

    ctx = AgentContext(
        config=config,
        run_dir=run_dir,
        tool_runner=tool_runner,
        evidence_store=evidence_store,
        event_sink=event_sink,
        logger=logger,
        budget=budget,
        target=target,
        scope=scope,
    )

    state = {
        "target": target.model_dump(mode="json"),
        "discovered_assets": [],
        "findings": [],
        "plans": [],
        "evidence": [],
        "artifacts": [],
        "session_status": SessionStatus(
            status="running", started_at=utc_now(), completed_at=None, error=None
        ).model_dump(mode="json"),
        "recon_artifacts": [],
    }

    workflow = build_workflow(ctx)
    result = workflow.invoke(state)

    assert result["session_status"]["status"] in {"running", "completed"}
    assert (run_dir / "report.md").exists()
