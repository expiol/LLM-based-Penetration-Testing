"""Top-level runtime session execution."""

from __future__ import annotations
import logging
from pathlib import Path
from killchain_docker.logging_utils import get_logger
from killchain_docker.runtime.assembly import build_runtime
from killchain_docker.runtime.config import RunArtifacts, RunConfig
from killchain_docker.runtime.events import EventRecorder
from killchain_docker.runtime.persistence import RunPersister, RuntimeStatusHeartbeat
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.run_state import RunState
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.tools.core import ExecutionPlane
from killchain_docker.llm.gateway import LLMClient

LOGGER = get_logger(__name__)


def record_runtime_exception(state: RunState, exc: BaseException) -> None:
    note = RunOutcomeStore(state).runtime_exception(exc)
    journal = RunJournal(state)
    if not journal.has_orchestration_note(note):
        journal.orchestration_note(note)


def run_assessment(
    config: RunConfig,
    *,
    execution_plane: ExecutionPlane | None = None,
    expected_flag: str | None = None,
    llm_client: LLMClient | None = None,
) -> RunArtifacts:
    """Run the full local workflow and persist artifacts."""
    recorder = EventRecorder(quiet=config.quiet)
    state, orchestrator, active_llm_client = build_runtime(
        config,
        recorder=recorder,
        execution_plane=execution_plane,
        expected_flag=expected_flag,
        llm_client=llm_client,
    )
    run_dir = Path(config.output_root) / state.run_id
    status_path = Path(config.status_path) if config.status_path else None
    token_ledger = getattr(active_llm_client, "token_ledger", None)
    persister = RunPersister(run_dir, recorder, status_path, token_ledger)
    recorder.bind_context(
        run_id=state.run_id, challenge=ChallengeProjection(state).name()
    )
    persister.write_config(config)
    persister.write_runtime_status(state, stage="initialized")
    orchestrator.checkpoint_callback = persister.write_state
    heartbeat = RuntimeStatusHeartbeat(persister, state)
    heartbeat.start()
    run_error: BaseException | None = None
    run_traceback = None
    try:
        orchestrator.run(max_cycles=config.max_cycles)
    except (KeyboardInterrupt, SystemExit) as exc:
        run_error = exc
        run_traceback = exc.__traceback__
        record_runtime_exception(state, exc)
        LOGGER.warning(
            "run interrupted; finalizing artifacts",
            exc_info=True,
            extra={"run_id": state.run_id},
        )
    except BaseException as exc:
        run_error = exc
        run_traceback = exc.__traceback__
        record_runtime_exception(state, exc)
        LOGGER.exception(
            "run failed; finalizing artifacts", extra={"run_id": state.run_id}
        )
    finally:
        heartbeat.stop()
        if token_ledger is not None:
            token_usage = token_ledger.to_dict()
            recorder.emit(
                f"[token usage] calls={token_usage['llm_calls']} prompt={token_usage['prompt_tokens']} completion={token_usage['completion_tokens']} total={token_usage['total_tokens']}",
                event_type="token_usage",
                llm_calls=token_usage["llm_calls"],
                prompt_tokens=token_usage["prompt_tokens"],
                completion_tokens=token_usage["completion_tokens"],
                total_tokens=token_usage["total_tokens"],
            )
        try:
            persister.write_all(state)
        except Exception:
            LOGGER.exception(
                "failed to persist final run artifacts", extra={"run_id": state.run_id}
            )
            if run_error is None:
                raise
    artifacts = RunArtifacts(
        run_id=state.run_id,
        run_dir=str(run_dir),
        state_path=str(persister.state_path),
        summary_path=str(persister.summary_path),
        report_path=str(persister.report_path),
        events_path=str(persister.events_path),
        config_path=str(persister.config_path),
        evidence_path=str(persister.evidence_path),
        compact_json_path=str(persister.compact_json_path),
        compact_markdown_path=str(persister.compact_markdown_path),
        status=str(RunOutcomeStore(state).status_value),
    )
    if run_error is not None:
        setattr(run_error, "run_artifacts", artifacts)
        raise run_error.with_traceback(run_traceback)
    return artifacts
