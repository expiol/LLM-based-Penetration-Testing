"""Binary analysis worker — strings, disassembly, and sandboxed execution.

The agent owns three related task types so the planner has a single
owner for binary inspection but clear cost/depth choices:

* ``artifact.binary_triage`` — fast pass (``file`` + ``strings``).  Used
  first; finds hardcoded flags / credentials / endpoint URLs / known
  algorithm names embedded in the binary.
* ``artifact.binary_disassembly`` — deep pass (``objdump`` based) that
  emits per-function disassembly + ``.rodata`` extraction + string xrefs.
  Used as a follow-up when triage yielded no flag candidate and the
  challenge category benefits from real reverse engineering (rev / pwn /
  crypto with a custom binary).
* ``artifact.binary_run`` — runtime probe.  Copies the binary + the
  other challenge files into a ``/tmp`` sandbox and tries several common
  invocations (no-args, ``--help``, with each non-binary file as a
  positional arg, with stdin from each file).  Captures stdout/stderr
  and any new files the binary writes; mines flag tokens from both.
  Used when disassembly didn't yield a flag either — many CTF binaries
  *are* the oracle for their algorithm (XOR self-inverse, decoder
  toggled by an arg, etc.).

The three task types are dispatched inside :meth:`run` so there is
exactly one worker class for binary work and no overlap risk between
workers.
"""

from __future__ import annotations

from killchain_docker.workers._helpers.planner_signals import planner_signals_for_tasks
from killchain_docker.workers.artifact._helpers import (
    challenge_meta,
    files_root_of,
    run_capability,
    success_report,
)
from killchain_docker.workers.artifact._simple_review import run_simple_review
from killchain_docker.workers.base import WorkerAgent
from killchain_docker.state import GlobalState, PlannerSignal, Task, WorkerReport
from killchain_docker.state.task_factory import build_flag_validation_tasks
from killchain_docker.tools import ToolCapability, capability_source


class BinaryTriageAgent(WorkerAgent):
    """Run strings/file (triage) or objdump (disassembly) on bundled binaries."""

    name = "binary-triage-agent"
    supported_task_types = (
        "artifact.binary_triage",
        "artifact.binary_disassembly",
        "artifact.binary_run",
        "artifact.deep_review",
    )
    required_context_keys = ("binary_files",)
    routing_summary = (
        "Inspect bundled binary artifacts — strings + file metadata for fast "
        "triage, objdump-based disassembly + .rodata extraction for deep "
        "reverse-engineering, or sandboxed execution to observe the binary's "
        "actual runtime behaviour when the algorithm itself is the challenge."
    )
    preferred_challenge_categories = ("rev", "pwn", "crypto", "misc")

    def supports(self, task: Task) -> bool:
        if task.task_type in {
            "artifact.binary_triage",
            "artifact.binary_disassembly",
            "artifact.binary_run",
        }:
            return True
        if task.task_type == "artifact.deep_review":
            kind = str(task.input_context.get("analysis_kind") or "").lower()
            return kind == "binary"
        return False

    #: Categories that benefit from automatic escalation to disassembly when
    #: the strings/file pass yielded no flag candidate.  Web / forensics
    #: rarely care about binary internals; rev / pwn / crypto / misc usually
    #: do.  Kept narrow so we do not waste a cycle on every category.
    _DISASM_FOLLOWUP_CATEGORIES = frozenset({"rev", "pwn", "crypto", "misc"})

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        if task.task_type == "artifact.binary_disassembly":
            # Deep pass: real objdump disassembly + .rodata.  Higher
            # timeout (objdump on large binaries can take a few seconds
            # per section) but smaller default file batch (we keep
            # ~10 KB of evidence per binary so the prompt stays bounded).
            report = run_simple_review(
                self, task, state,
                capability=ToolCapability.ARTIFACT_BINARY_DISASSEMBLE,
                evidence_label="binary disassembly",
                input_field="binary_files",
                processed_field="inspected_binaries",
                max_files_default=4,
                timeout_default=180,
                summary_suffix="produced disassembly evidence for bundled binaries",
                role_addition=(
                    "Read the per-function disassembly and .rodata excerpts to "
                    "infer the algorithm before running a script experiment; do NOT guess "
                    "constants when the kept functions show concrete values."
                ),
            )
            # When disassembly also fails to find a flag, escalate to live
            # binary execution.  Many CTF binaries ARE the oracle for the
            # algorithm they encode (XOR self-inverse, etc.) so running
            # them on the bundled inputs in a /tmp sandbox is the next
            # cheapest signal source.
            self._maybe_queue_binary_run_followup(task, state, report)
            return report

        if task.task_type == "artifact.binary_run":
            # Sandboxed execution: copy binary + challenge files to /tmp
            # and run several invocation patterns.  Each invocation is
            # capped at 15 s; total wall clock ~ 6 * 15 = 90 s, plus
            # filesystem snapshot overhead.  Generous worker timeout to
            # leave headroom.  The execution tool handles arg generation,
            # workdir copy, and cleanup.
            return self._run_binary_execution(task, state)

        # Fast pass: strings + file metadata (the original triage path).
        report = run_simple_review(
            self, task, state,
            capability=ToolCapability.ARTIFACT_BINARY_TRIAGE,
            evidence_label="binary triage",
            input_field="binary_files",
            processed_field="inspected_binaries",
            max_files_default=6,
            timeout_default=120,
            summary_suffix="inspected bundled binaries",
            role_addition=(
                "Pay special attention to interesting strings, URLs, and command paths in the binary."
            ),
        )
        # Auto-escalate to deep disassembly when the cheap pass yielded
        # no flag and the challenge category benefits from real RE.  This
        # is generic (no algorithm-specific keywords) and bounded by the
        # disassembly task's dedupe key so we never queue it twice for
        # the same binary set.
        self._maybe_queue_disassembly_followup(task, state, report)
        return report

    def _maybe_queue_binary_run_followup(
        self,
        task: Task,
        state: GlobalState,
        report: WorkerReport,
    ) -> None:
        """After disassembly without a flag, queue a sandboxed run.

        Same category filter as the triage→disassembly escalation: only
        rev/pwn/crypto/misc challenges plausibly benefit from observing
        the binary's actual runtime behaviour.
        """
        if not report.success:
            return
        flag_candidates = report.output_context.get("flag_candidates") or []
        if flag_candidates:
            return
        inspected = report.output_context.get("inspected_binaries") or []
        if not inspected:
            return
        cmeta = state.metadata.get("challenge", {}) or {}
        category = str(cmeta.get("category") or "").strip().lower()
        if category and category not in self._DISASM_FOLLOWUP_CATEGORIES:
            return

        from killchain_docker.state.task_factory import (
            build_binary_run_task,
        )
        files_root = str(task.input_context.get("files_root") or "/home/ctfplayer/ctf_files")
        followup = build_binary_run_task(
            files_root=files_root,
            binary_files=list(inspected),
        )
        report.planner_signals.append(
            PlannerSignal(
                source_task_id=task.task_id,
                worker_name=self.name,
                summary="Disassembly found no flag; sandboxed binary execution may expose runtime behavior.",
                suggested_task_type=followup.task_type,
                suggested_input_context=dict(followup.input_context),
                rationale="Runtime execution is the next binary-analysis signal after static disassembly.",
                metadata={"suggested_task": followup.model_dump(mode="json")},
            )
        )
        report.notes.append(
            f"{self.name} suggested sandboxed binary_run follow-up "
            f"({followup.task_id}) - disassembly found no flag in {len(inspected)} binary(ies)."
        )

    def _run_binary_execution(self, task: Task, state: GlobalState) -> WorkerReport:
        """Probe binary behaviour through the binary execution capability."""
        cm = challenge_meta(state)
        challenge_files = list(cm.get("files") or [])
        capability = ToolCapability.ARTIFACT_BINARY_EXECUTE
        bundle, fail = run_capability(
            self,
            task=task,
            capability=capability,
            timeout_s=int(task.input_context.get("timeout_s", 240)),
            metadata={
                "files_root": files_root_of(task),
                "binary_files": task.input_context.get("binary_files") or [],
                "challenge_files": challenge_files,
                "max_files": int(task.input_context.get("max_files", 3)),
                "per_invocation_timeout_s": int(
                    task.input_context.get("per_invocation_timeout_s", 15)
                ),
                "max_invocations_per_binary": int(
                    task.input_context.get("max_invocations_per_binary", 6)
                ),
            },
            label="binary run",
        )
        if fail is not None:
            return fail
        assert bundle is not None
        output_context = dict(bundle.parsed.output_context)
        flag_candidates = list(output_context.get("flag_candidates") or [])
        suggested_tasks = build_flag_validation_tasks(
            flag_candidates, source=capability_source(capability)
        )
        inspected = list(output_context.get("inspected_binaries") or [])
        return success_report(
            worker_name=self.name,
            task=task,
            bundle=bundle,
            output_context=output_context,
            planner_signals=planner_signals_for_tasks(source_task=task, worker_name=self.name, tasks=suggested_tasks),
            notes=list(bundle.parsed.notes) + [
                f"{self.name} executed bundled binaries in /tmp sandbox."
            ],
            success=bool(inspected),
            error=(
                None
                if inspected
                else "binary.execute: 0 binaries actually executed; check binary_files context."
            ),
        )

    def _maybe_queue_disassembly_followup(
        self,
        task: Task,
        state: GlobalState,
        report: WorkerReport,
    ) -> None:
        if not report.success:
            return
        flag_candidates = report.output_context.get("flag_candidates") or []
        if flag_candidates:
            return
        inspected = report.output_context.get("inspected_binaries") or []
        if not inspected:
            return
        challenge_meta = state.metadata.get("challenge", {}) or {}
        category = str(challenge_meta.get("category") or "").strip().lower()
        if category and category not in self._DISASM_FOLLOWUP_CATEGORIES:
            return

        # Local import to keep workers.artifact.binary side-effect free at
        # import time (state.task_factory pulls in pydantic models).
        from killchain_docker.state.task_factory import (
            build_binary_disassembly_task,
        )

        files_root = str(task.input_context.get("files_root") or "/home/ctfplayer/ctf_files")
        followup = build_binary_disassembly_task(
            files_root=files_root,
            binary_files=list(inspected),
        )
        report.planner_signals.append(
            PlannerSignal(
                source_task_id=task.task_id,
                worker_name=self.name,
                summary="Binary triage found no flag; disassembly may expose the algorithm.",
                suggested_task_type=followup.task_type,
                suggested_input_context=dict(followup.input_context),
                rationale="Deep disassembly is the next binary-analysis signal after strings/file triage.",
                metadata={"suggested_task": followup.model_dump(mode="json")},
            )
        )
        report.notes.append(
            f"{self.name} suggested deep disassembly follow-up "
            f"({followup.task_id}) - triage found no flag in {len(inspected)} binary(ies)."
        )
