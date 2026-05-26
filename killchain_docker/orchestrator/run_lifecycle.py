"""Top-level run lifecycle, interrupts, and uncaught runtime errors."""

from __future__ import annotations

import killchain_docker.orchestrator.background_flags as background_flags
from killchain_docker.llm.gateway import LLMClientError
from killchain_docker.orchestrator.run_termination import RunTerminationController
from killchain_docker.orchestrator.runtime_events import RuntimeEventController
from killchain_docker.orchestrator.todo_status_commands import TodoStatusCommands
from killchain_docker.state.journal import RunJournal
from killchain_docker.state.outcome import RunOutcomeStore
from killchain_docker.state.run_state import RunState


class RunLifecycleController:
    """Owns top-level run lifecycle, interrupts, and uncaught runtime errors."""

    def __init__(
        self,
        *,
        state: RunState,
        commands: TodoStatusCommands,
        events: RuntimeEventController,
        journal: RunJournal,
        termination: RunTerminationController,
        background_flags: background_flags.BackgroundFlagValidationController,
    ) -> None:
        self.state = state
        self.commands = commands
        self.events = events
        self.journal = journal
        self.termination = termination
        self.background_flags = background_flags
        self.outcome = RunOutcomeStore(state)

    def start(self) -> None:
        self.outcome.start(touch=False)
        self.background_flags.start()

    def stop_background(self) -> None:
        self.background_flags.stop()

    def handle_uncaught_llm_error(self, *, cycle: int, exc: LLMClientError) -> None:
        if self.outcome.has_stop_reason("llm_error"):
            return
        self.events.emit(f"[cycle {cycle}] LLM error - aborting run")
        self.termination.mark_llm_error(cycle, "runtime", exc)
        self.events.checkpoint()

    def handle_background_flag_solved(self, *, cycle: int) -> None:
        self.events.emit(
            f"[cycle {cycle}] background flag validation solved - halting run"
        )

    def handle_interrupt(self, exc: KeyboardInterrupt | SystemExit) -> None:
        reason = f"run interrupted by {type(exc).__name__}"
        self.commands.interrupt_running(reason)
        self.outcome.interrupted("interrupted", touch=False)
        self.journal.orchestration_note(reason)
        self.events.emit(f"[interrupt] {reason}; marked running todos as interrupted")
        self.events.checkpoint()
