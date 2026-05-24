"""Base abstraction for orchestrator-managed workers.

This module owns the :class:`WorkerAgent` abstract base class for the
persona-worker runtime.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable
import json
import re
from typing import Any

from killchain_docker.evidence_context import EvidenceContextBuilder
from killchain_docker.llm import LLMClient, LLMClientError
from killchain_docker.prompt_bounds import bounded_value, trim_text
from killchain_docker.prompt_projection import (
    artifacts as prompt_artifacts,
    execution_record as prompt_execution_record,
    worker_todo as prompt_worker_todo,
    working_memory as prompt_working_memory,
)
from killchain_docker.reasoning import ToolUseDecision
from killchain_docker.state import FlagCandidate, RunState, TodoItem, WorkerResult
from killchain_docker.tools import (
    ExecutionPlane,
    ToolCapability,
    ToolExecutionBundle,
    ToolExecutionError,
    ToolGateway,
)
from killchain_docker.workers.tool_metadata import tool_metadata_contract
from killchain_docker.workers.routing import PersonaRoutingPolicy


# ===========================================================================
# WorkerAgent — abstract base
# ===========================================================================


class WorkerAgent(ABC):
    """Abstract persona worker that can handle high-level todos."""

    name: str
    supported_todo_kinds: tuple[str, ...]
    routing_summary: str = ""
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()
    supported_dispatch_profiles: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
        tool_gateway: ToolGateway | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.execution_plane = execution_plane
        self.tool_gateway = tool_gateway or (
            ToolGateway(execution_plane) if execution_plane is not None else None
        )
        self.progress_callback: Callable[[RunState, TodoItem, str], None] | None = None
        self.flag_candidate_callback: Callable[
            [RunState, TodoItem, Iterable[FlagCandidate]],
            None,
        ] | None = None

    def report_progress(self, state: RunState, task: TodoItem, message: str) -> None:
        if self.progress_callback is None:
            return
        self.progress_callback(state, task, message)

    def report_flag_candidates(
        self,
        state: RunState,
        task: TodoItem,
        candidates: Iterable[FlagCandidate],
    ) -> None:
        if self.flag_candidate_callback is None:
            return
        self.flag_candidate_callback(state, task, list(candidates))

    def supports(self, todo: TodoItem) -> bool:
        return True

    def can_route_task(self, todo: TodoItem, state: RunState) -> tuple[bool, str | None]:
        """Return whether the worker is eligible for a routed dispatch."""

        return PersonaRoutingPolicy.can_route_task(self, todo, state)

    def run_capability(
        self,
        *,
        task: TodoItem,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
    ) -> ToolExecutionBundle:
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway but none is configured."
            )
        return self.tool_gateway.run(
            task_id=getattr(task, "todo_id", getattr(task, "task_id", "")),
            capability=capability,
            metadata=metadata,
            timeout_s=timeout_s,
        )

    def choose_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        allowed_capabilities: list[ToolCapability | str] | None = None,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision:
        """Ask the LLM to choose one lower-level tool capability for a task."""

        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client for tool selection."
            )
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway for tool selection."
            )
        allowed = {
            ToolCapability(capability)
            for capability in (
                allowed_capabilities or list(self.tool_gateway.specs.keys())
            )
        }
        allowed_values = sorted(capability.value for capability in allowed)
        catalog = [
            {
                "capability": capability.value,
                "tool_name": spec.tool_name,
                "default_timeout_s": spec.default_timeout_s,
                "metadata_contract": tool_metadata_contract(capability),
            }
            for capability, spec in self.tool_gateway.specs.items()
            if capability in allowed
        ]
        # Trim evidence when script generation is likely to preserve output budget
        likely_script = any(
            kw in task.goal.lower()
            for kw in ("script", "decrypt", "brute", "write", "compute", "solve")
        )
        max_evidence = 5 if likely_script else 10
        evidence_context = EvidenceContextBuilder(max_records=max_evidence).build(
            state, allowed_capabilities=allowed
        )
        correction_context = self._correction_context(
            state=state,
            task=task,
            prior_steps=prior_steps,
        )

        user_payload = {
            # ACTION-CRITICAL: tool catalog first for attention proximity
            "tool_catalog": catalog,
            "allowed_capabilities": allowed_values,
            "tool_use_rules": self._tool_use_rules(allowed),
            # TASK CONTEXT
            "worker_name": self.name,
            "todo": prompt_worker_todo(task),
            "artifacts": prompt_artifacts(state, limit=20),
            "working_memory": prompt_working_memory(state),
            # EVIDENCE
            "recent_evidence_context": evidence_context,
            "prior_steps": bounded_value(prior_steps or [], width=700, list_limit=4, dict_limit=14),
            # BACKGROUND (least critical)
            "state_summary": state.summary(),
            "recent_failures": [
                prompt_execution_record(record)
                for record in state.execution_log[-6:]
                if not record.success
            ],
        }
        if correction_context:
            constraints = self._execution_constraints(
                state=state,
                task=task,
                correction_context=correction_context,
                prior_steps=prior_steps or [],
            )
            if constraints:
                correction_context["execution_constraints"] = constraints
            user_payload["correction_context"] = correction_context

        allowed_str = ", ".join(f"'{v}'" for v in allowed_values)
        script_reminder = (
            "CRITICAL: For script.exec, 'script_code' is MANDATORY and must contain "
            "the COMPLETE executable source code as a string — not a description of what "
            "to write, but the actual runnable Python/bash code. "
            "Generated scripts MUST be bounded: no unbounded brute force, no per-step "
            "loops over huge counters, no network waits without socket timeouts, and no "
            "package installation. If a task involves a large skip/exponent/search space, "
            "use a logarithmic or algebraic method, cap diagnostic variants, and print "
            "intermediate values plus failure reasons. Prefer Python stdlib. If an "
            "optional third-party import is useful, catch ImportError and include a "
            "stdlib fallback in the same script. "
            "When adapting legacy Python or writeup code for binary data, port bytes/text "
            "boundaries deliberately: open artifacts in binary mode, use bytes literals, "
            "bytes.fromhex()/bytes.hex(), and remember that iterating bytes yields ints "
            "in Python 3. "
        ) if ToolCapability.SCRIPT_EXEC in allowed else ""
        shell_reminder = (
            "For shell.exec, 'command' is MANDATORY and must contain the full shell "
            "command to execute via bash -c. You can use any tool installed in the "
            "container: curl, nmap, sqlmap, strings, file, binwalk, r2, tshark, etc. "
            "Use curl/wget only for HTTP/HTTPS; for tcp:// or custom services choose "
            "script.exec with Python sockets and explicit timeouts. "
            "Do not embed complex Python in python -c; if Python needs with/if/for/while, "
            "file parsing, or multi-line logic, choose script.exec instead. "
            "Do not run apt/yum/apk/pip/npm installs or package-manager updates; "
            "if a tool is missing, record that fact and pivot to installed tools. "
            "Shell commands run with challenge-file snapshot protection; any writes "
            "under files_root are discarded after execution, so print evidence to stdout. "
            "Use CTF_TEMP_DIR for scratch files; it is deleted after the tool call. "
            "CTF_ORIGINAL_FILES_ROOT points to a separate pristine snapshot for comparing "
            "sizes/hashes during the same command; read from it, but never write to it. "
            "When running a challenge binary or tool that may derive an output path from "
            "the input path, copy the input to CTF_TEMP_DIR with a non-colliding name "
            "first and verify the output path is not the same as the input. "
        ) if ToolCapability.SHELL_EXEC in allowed else ""
        decision = self.llm_client.generate_json(
            system_prompt=(
                f"You are {self.name}. Your ONLY available capabilities are: [{allowed_str}]. "
                "You MUST choose exactly one capability from this list. Any other capability "
                "will be REJECTED — do not select capabilities you saw in evidence from other workers. "
                "Provide the metadata arguments needed by that capability using only the "
                "field names listed in its metadata_contract. "
                f"{shell_reminder}"
                f"{script_reminder}"
                "Use recent_evidence_context as grounded facts from previous tools. "
                "If prior_steps is non-empty, use those results to inform your choice — "
                "do not repeat a tool that already produced its evidence. "
                "If correction_context is present, you MUST fix the identified error "
                "in your next script — do not repeat the same broken approach. "
                "When the current todo or correction_context states a corrected value "
                "from a previous failure, it overrides older reference/source code and "
                "older evidence unless your next bounded diagnostic disproves it. "
                "If correction_context.execution_constraints contains "
                "do_not_iterate_values, your script_code MUST NOT put those exact "
                "values into range(), loop bounds, sleeps, brute-force searches, or "
                "linear counters. Use listed bounded_counter_candidates first, or "
                "explicitly skip the oversized interpretation and continue bounded "
                "enumeration. "
                "Do not depend on files generated by earlier shell.exec/script.exec calls, "
                "including files written under files_root; tool workspaces are snapshots. "
                "Read original challenge files directly or regenerate needed artifacts in "
                "the same tool call. "
                "Stay inside authorized_scope and files_root. Do not pivot to localhost, "
                "127.0.0.1, or unrelated local services unless they are explicitly in "
                "authorized_scope. Do not search ambient directories such as /home outside "
                "files_root, /root, /etc, /tmp, /var, /opt, or shell startup files for "
                "flags or secrets unless a todo explicitly identifies those paths as "
                "challenge artifacts. "
                "Use working_memory as established facts from prior analysis. "
                "Use memory_updates only for facts already grounded in current state "
                "or prior evidence; do not use memory_updates to predict what the "
                "tool you are about to run will prove. Put unverified ideas in "
                "hypothesis instead. "
                "Return only JSON matching ToolUseDecision."
            ),
            user_prompt=json.dumps(
                user_payload,
                ensure_ascii=True,
                indent=2,
            ),
            schema=ToolUseDecision,
            temperature=0.1,
        )
        try:
            selected = ToolCapability(decision.capability)
        except ValueError as exc:
            raise ToolExecutionError(
                f"{self.name} selected invalid tool capability {decision.capability!r}; "
                f"allowed capabilities: {', '.join(allowed_values)}"
            ) from exc
        if selected not in allowed:
            raise ToolExecutionError(
                f"{self.name} selected unavailable tool capability {selected.value!r}; "
                f"allowed capabilities: {', '.join(allowed_values)}"
            )
        return decision

    def choose_fixed_tool_use(
        self,
        *,
        task: TodoItem,
        state: RunState,
        capability: ToolCapability | str,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> ToolUseDecision:
        """Ask the LLM for metadata after dispatch has fixed the capability."""

        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client for tool metadata."
            )
        if self.tool_gateway is None:
            raise ToolExecutionError(
                f"{type(self).__name__} requires a ToolGateway for tool metadata."
            )
        selected = ToolCapability(capability)
        evidence_context = EvidenceContextBuilder(max_records=5).build(
            state,
            allowed_capabilities={selected},
        )
        correction_context = self._correction_context(
            state=state,
            task=task,
            prior_steps=prior_steps,
        )
        user_payload = {
            "fixed_capability": selected.value,
            "metadata_contract": tool_metadata_contract(selected),
            "tool_use_rules": self._tool_use_rules({selected}),
            "worker_name": self.name,
            "todo": prompt_worker_todo(task),
            "artifacts": prompt_artifacts(state, limit=12),
            "working_memory": prompt_working_memory(state),
            "recent_evidence_context": evidence_context,
            "prior_steps": bounded_value(prior_steps or [], width=700, list_limit=4, dict_limit=14),
            "recent_failures": [
                prompt_execution_record(record)
                for record in state.execution_log[-4:]
                if not record.success
            ],
        }
        if correction_context:
            constraints = self._execution_constraints(
                state=state,
                task=task,
                correction_context=correction_context,
                prior_steps=prior_steps or [],
            )
            if constraints:
                correction_context["execution_constraints"] = constraints
            user_payload["correction_context"] = correction_context

        fixed_rules = (
            "The router has already selected the capability. Do not choose or "
            "compare tools. Return ToolUseDecision with capability exactly "
            f"'{selected.value}' and metadata matching metadata_contract. "
        )
        if selected == ToolCapability.SCRIPT_EXEC:
            fixed_rules += (
                "metadata.script_code must be complete bounded runnable source, "
                "prefer Python stdlib, use CTF_FILES_ROOT or relative paths for "
                "challenge files, use CTF_TEMP_DIR/tempfile for scratch, set network "
                "timeouts, print concise evidence, and do not install packages. "
            )
        elif selected == ToolCapability.SHELL_EXEC:
            fixed_rules += (
                "metadata.command must be a complete bash command using installed "
                "tools, with stderr visible and no package installation. "
            )

        decision = self.llm_client.generate_json(
            system_prompt=(
                f"You are {self.name}. {fixed_rules}"
                "Use recent_evidence_context and working_memory as grounded facts. "
                "If correction_context is present, fix that concrete runtime issue. "
                "Do not depend on files generated by previous tool calls unless the "
                "current todo references durable artifacts; regenerate transient "
                "scratch outputs in this same call. Stay inside authorized_scope and "
                "files_root. Return only JSON matching ToolUseDecision."
            ),
            user_prompt=json.dumps(
                user_payload,
                ensure_ascii=True,
                indent=2,
            ),
            schema=ToolUseDecision,
            temperature=0.1,
        )
        if ToolCapability(decision.capability) != selected:
            raise ToolExecutionError(
                f"{self.name} changed fixed capability from {selected.value!r} "
                f"to {decision.capability!r}"
            )
        return decision

    def _correction_context(
        self,
        *,
        state: RunState,
        task: TodoItem,
        prior_steps: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        # Bounded correction context from local prior steps plus recent
        # same-todo script evidence. The evidence lookup matters across worker
        # retries because local prior_steps is reset on each dispatch.
        correction_context = self._recent_script_failure_context(state, task)
        if not prior_steps:
            return correction_context

        last = prior_steps[-1]
        if (
            last.get("capability") == "script.exec"
            and (last.get("returncode") not in (None, 0) or not last.get("flag_candidates"))
        ):
            failure_kind = last.get("failure_kind")
            if not failure_kind and last.get("near_miss_candidates"):
                failure_kind = "near_miss"
            local_context = {
                "instruction": self._script_correction_instruction(failure_kind),
                "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
                "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
                "failure_kind": failure_kind,
                "failure_detail": last.get("failure_detail"),
            }
            if self._is_critical_script_failure(correction_context):
                local_context["previous_critical_failure"] = correction_context
            else:
                correction_context = local_context
        elif (
            last.get("capability") == "shell.exec"
            and last.get("returncode") not in (None, 0)
        ):
            failure_kind = last.get("failure_kind") or "shell_failure"
            instruction = (
                "The previous shell command failed. Analyze stderr/stdout and "
                "do not repeat the same command. If the command embedded Python "
                "with python -c and hit SyntaxError or needed with/if/for/while "
                "or file parsing, choose script.exec and provide complete "
                "multi-line script_code instead."
            )
            if failure_kind == "unbounded_extraction_blocked":
                instruction = (
                    "The previous shell command was blocked because it attempted "
                    "unbounded extraction. Do not repeat raw binwalk -e or dd bs=1 "
                    "skip without count. Use the binwalk capability with "
                    "extract=true/max_extract_mb, or choose script.exec and do "
                    "bounded Python seek/read using known offsets, archive EOF/EOCD, "
                    "or a strict byte count."
                )
            elif failure_kind == "non_http_url_blocked":
                instruction = (
                    "The previous shell command used curl/wget for a non-HTTP "
                    "endpoint. Do not retry curl, wget, or shell failure masking "
                    "such as `|| echo`. For tcp:// or custom services, choose "
                    "script.exec and write a small stdlib socket harness with "
                    "connect/read timeouts <=5 seconds, an overall deadline <=45 "
                    "seconds, explicit send/receive framing, and concise diagnostics."
                )
            elif failure_kind == "stderr_suppression_blocked":
                instruction = (
                    "The previous shell command hid stderr, which prevents reliable "
                    "repair. Re-run a smaller diagnostic command with stderr visible "
                    "or redirect stderr to stdout using 2>&1. Do not use 2>/dev/null, "
                    "&>/dev/null, or failure masking while checking whether a tool, "
                    "path, offset, archive, or filesystem operation works."
                )
            elif failure_kind == "missing_tool":
                instruction = (
                    "The previous shell command called a tool that is not installed. "
                    "Do not keep the missing command at the front of an && chain. "
                    "Probe optional tools with command -v or separate commands, then "
                    "pivot to installed equivalents, dedicated capabilities, or "
                    "script.exec with stdlib parsing. Preserve stdout/stderr so the "
                    "next step knows exactly which fallback worked."
                )
            correction_context = {
                "instruction": instruction,
                "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
                "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
                "failure_kind": failure_kind,
                "failure_detail": last.get("failure_detail"),
            }
        elif last.get("failure_kind") == "non_http_url_blocked":
            correction_context = {
                "instruction": (
                    "The previous tool choice used curl for a non-HTTP endpoint. "
                    "Curl is only for HTTP/HTTPS. For tcp:// or custom services, "
                    "choose script.exec and write a small stdlib socket harness with "
                    "connect/read timeouts <=5 seconds, an overall deadline <=45 "
                    "seconds, explicit send/receive framing, and concise diagnostics."
                ),
                "last_stderr": trim_text(last.get("stderr_preview", ""), width=700),
                "last_stdout": trim_text(last.get("stdout_preview", ""), width=700),
                "failure_kind": "non_http_url_blocked",
                "failure_detail": last.get("failure_detail"),
            }
        return correction_context

    @staticmethod
    def _is_critical_script_failure(context: dict[str, Any] | None) -> bool:
        if not context:
            return False
        return str(context.get("failure_kind") or "") in {
            "timeout",
            "unbounded_loop_guard",
        }

    @classmethod
    def _recent_script_failure_context(
        cls,
        state: RunState,
        task: TodoItem,
    ) -> dict[str, Any] | None:
        same_task: list[Any] = []
        other_tasks: list[Any] = []
        task_id = getattr(task, "todo_id", "")
        for evidence in reversed(list(state.evidence.values())):
            if evidence.tool_name != "script_exec":
                continue
            extracted = evidence.extracted if isinstance(evidence.extracted, dict) else {}
            ctx = extracted.get("output_context")
            if not isinstance(ctx, dict):
                continue
            failure_kind = ctx.get("failure_kind")
            returncode = ctx.get("returncode")
            has_failed = failure_kind not in (None, "", "none") or returncode not in (None, 0, "")
            if not has_failed:
                continue
            if evidence.task_id == task_id:
                same_task.append((evidence, ctx))
            else:
                other_tasks.append((evidence, ctx))

        for evidence, ctx in same_task + other_tasks[:1]:
            failure_kind = ctx.get("failure_kind")
            if failure_kind in (None, "", "none") and ctx.get("returncode") in (None, 0, ""):
                continue
            return {
                "instruction": cls._script_correction_instruction(failure_kind),
                "last_stderr": trim_text(ctx.get("stderr", ""), width=700),
                "last_stdout": trim_text(ctx.get("stdout", ""), width=700),
                "failure_kind": failure_kind,
                "failure_detail": ctx.get("failure_detail"),
                "source_evidence_id": evidence.evidence_id,
            }
        return None

    @classmethod
    def _execution_constraints(
        cls,
        *,
        state: RunState,
        task: TodoItem,
        correction_context: dict[str, Any],
        prior_steps: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build hard execution hints from prior runtime guard failures."""

        failure_kind = str(correction_context.get("failure_kind") or "")
        if failure_kind not in {"timeout", "unbounded_loop_guard"}:
            return {}

        failure_text = "\n".join(
            str(correction_context.get(key) or "")
            for key in ("last_stderr", "last_stdout", "failure_detail")
        )
        for step in prior_steps[-2:]:
            failure_text += "\n" + str(step.get("stderr_preview") or "")
            failure_text += "\n" + str(step.get("stdout_preview") or "")

        blocked = cls._large_counter_values(failure_text)
        bounded = cls._bounded_counter_candidates(state=state, task=task)
        constraints: dict[str, Any] = {}
        if blocked:
            constraints["do_not_iterate_values"] = blocked
        if bounded:
            constraints["bounded_counter_candidates"] = bounded
        if blocked or bounded:
            constraints["rule"] = (
                "Do not repeat oversized counters from prior guard failures. "
                "Before any linear loop, choose a bounded evidence-backed "
                "counter or prove a logarithmic fast-forward."
            )
        return constraints

    @staticmethod
    def _large_counter_values(text: str, *, limit: int = 5_000_000) -> list[int]:
        values: list[int] = []
        seen: set[int] = set()
        for match in re.finditer(r"\b0x[0-9a-fA-F]{6,}\b|\b\d{7,}\b", text):
            token = match.group(0)
            try:
                value = int(token, 16) if token.lower().startswith("0x") else int(token)
            except ValueError:
                continue
            if value <= limit or value in seen:
                continue
            seen.add(value)
            values.append(value)
            if len(values) >= 8:
                break
        return values

    @staticmethod
    def _bounded_counter_candidates(
        *,
        state: RunState,
        task: TodoItem,
        limit: int = 5_000_000,
    ) -> list[dict[str, object]]:
        candidates: list[dict[str, object]] = []
        seen: set[tuple[str, int]] = set()
        counter_words = re.compile(
            r"(?:count|counter|skip|limit|length|size|offset|round|iteration|bound)",
            re.IGNORECASE,
        )

        def add(label: str, value: int, source: str) -> None:
            key = (label, value)
            if value < 0 or value > limit or key in seen:
                return
            seen.add(key)
            candidates.append({"label": label, "value": value, "source": source})

        def scan_text(source: str, text: str) -> None:
            for match in re.finditer(
                r"\b([A-Za-z_][A-Za-z0-9_ -]{0,40})\s*[:=]\s*(0x[0-9a-fA-F]+|\d+)\b",
                text,
            ):
                label = re.sub(r"\s+", "_", match.group(1).strip()).strip("_")
                if not label or not counter_words.search(label):
                    continue
                words = [word.lower() for word in re.findall(r"[A-Za-z]+", label)]
                for index, word in enumerate(words):
                    if counter_words.search(word):
                        if index and words[index - 1] in {
                            "corrected", "bounded", "expected", "actual", "declared",
                        }:
                            label = f"{words[index - 1]}_{word}"
                        else:
                            label = word
                        break
                token = match.group(2)
                try:
                    value = int(token, 16) if token.lower().startswith("0x") else int(token)
                except ValueError:
                    continue
                add(label[:48], value, source)

        scan_text("todo.goal", task.goal)
        scan_text("todo.constraints", "\n".join(task.constraints))
        scan_text("todo.success_criteria", "\n".join(task.success_criteria))
        for key, value in task.context.items():
            if isinstance(value, int) and counter_words.search(str(key)):
                add(str(key)[:48], value, "todo.context")
            elif isinstance(value, str):
                scan_text(f"todo.context.{key}", value)
        for key, value in state.working_memory.items():
            if isinstance(value, int) and counter_words.search(str(key)):
                add(str(key)[:48], value, "working_memory")
            elif isinstance(value, str):
                if counter_words.search(str(key)):
                    for token in re.findall(r"\b0x[0-9a-fA-F]+\b|\b\d+\b", value):
                        try:
                            parsed = int(token, 16) if token.lower().startswith("0x") else int(token)
                        except ValueError:
                            continue
                        add(str(key)[:48], parsed, "working_memory")
                scan_text(f"working_memory.{key}", value)
            if len(candidates) >= 12:
                break
        return candidates[:12]

    @staticmethod
    def _tool_use_rules(allowed: set[ToolCapability]) -> list[str]:
        rules = [
            "Choose exactly one capability from tool_catalog.",
            "Use recent_evidence_context before repeating diagnostics already present there.",
        ]
        if ToolCapability.SHELL_EXEC in allowed:
            rules.extend(
                [
                    "For shell.exec, put the full command string in 'command'. "
                    "Use installed tools only; if a dependency is missing, record that "
                    "fact and choose another available route.",
                    "Do not use shell.exec for complex Python one-liners. If Python "
                    "needs with/if/for/while, file parsing, or multi-line logic, choose "
                    "script.exec instead.",
                    "Do not use shell.exec for package installation or updates "
                    "(apt, yum, dnf, apk, pacman, brew, pip, npm, yarn, gem, cargo, go).",
                    "Prefer shell.exec for bounded inspection, installed-tool diagnostics, "
                    "and simple authorized network probes.",
                    "Keep file searches under files_root or explicit challenge paths "
                    "from todo context/evidence.",
                    "Any shell.exec writes under files_root are discarded after the command. "
                    "Use CTF_TEMP_DIR instead of /tmp for scratch files; direct /tmp "
                    "references are blocked. "
                    "CTF_ORIGINAL_FILES_ROOT is a separate pristine snapshot for comparing "
                    "file sizes/hashes during one command; read from it, never write to it.",
                ]
            )
        if ToolCapability.SCRIPT_EXEC in allowed:
            rules.extend(
                [
                    "For script.exec, provide complete self-contained script_code and print "
                    "diagnostics/results to stdout.",
                    "Do not assume third-party Python packages are installed "
                    "(z3, rstr, exrex, pwntools, requests, Crypto, numpy, etc.). "
                    "Prefer stdlib. If you use an optional import, catch ImportError "
                    "and include a stdlib fallback in the same script; never spend a "
                    "run step installing packages.",
                    "Keep generated scripts syntactically simple: put control flow in "
                    "functions and call main() under if __name__ == '__main__'. Do not "
                    "use return outside a function, break/continue outside a loop, or "
                    "top-level fragments that cannot pass ast.parse.",
                    "script.exec starts in a disposable copy of files_root; use relative paths "
                    "or CTF_FILES_ROOT for challenge files and generated artifacts. Use "
                    "CTF_TEMP_DIR or tempfile for scratch files. Do not write to /tmp, "
                    "/home outside CTF_FILES_ROOT, or CTF_ORIGINAL_FILES_ROOT.",
                    "CTF_ORIGINAL_FILES_ROOT is a separate pristine snapshot for checking "
                    "original sizes/hashes while the disposable work copy is being modified.",
                    "Prefer script.exec for multi-step logic, parsing, computation, and "
                    "bounded solvers.",
                    "Treat the current todo goal, correction_context, and working_memory as "
                    "higher-priority facts than older evidence or reference/source code. If "
                    "a corrected value is explicitly stated there, use that value verbatim "
                    "unless a fresh bounded diagnostic proves it wrong.",
                    "When todo context, knowledge hints, evidence, or working memory include "
                    "reference/source code for an algorithm, port its state update order and "
                    "data conversions faithfully before substituting an equivalent-looking "
                    "formula.",
                    "When porting Python 2 or writeup snippets for binary formats, make "
                    "the bytes/text model explicit: use rb/wb, bytes literals, "
                    "bytes.fromhex(), bytes.hex(), and integer-safe XOR helpers.",
                    "When the task context has execution_closure, make the script prove "
                    "the path before trusting output: extract inputs, run a small self-check "
                    "when possible, score bounded interpretations, and print candidate provenance.",
                    "When recovered output is a derived artifact instead of plaintext, "
                    "regenerate or read it in the same script and inspect it with "
                    "format-appropriate semantics before declaring no candidate.",
                    "Every script.exec script must terminate within its timeout by design: "
                    "bound loops, cap brute-force/search variants, set socket/subprocess "
                    "timeouts, and avoid package installation.",
                    "For network or protocol scripts, prefer Python stdlib modules "
                    "(socket, ssl, http.client, urllib, telnetlib where available). Set "
                    "connect/read socket timeouts <=5 seconds and keep the overall script "
                    "deadline <=45 seconds. Do not switch to localhost/127.0.0.1 unless "
                    "that endpoint is explicitly in authorized_scope.",
                    "When evidence gives several plausible interpretations, enumerate only "
                    "bounded combinations, score their outputs, and print why rejected "
                    "interpretations failed.",
                    "For PCAP extraction tasks, if tshark/tcpflow filters are empty or "
                    "unavailable, parse packet records or exported payload fields with "
                    "stdlib logic and reassemble streams; do not only grep the raw pcap "
                    "container for embedded-file magic bytes.",
                    "Validate candidate quality before declaring success: require the expected "
                    "flag shape or high-printability plaintext. Do not exit early after a "
                    "low-quality possible candidate; print its score/reason and continue "
                    "bounded enumeration.",
                    "When a script recovers plaintext, search the full plaintext bytes before "
                    "printing a preview. Look for canonical brace flags and long bare CTF "
                    "tokens such as uppercase or separator-heavy words; print any candidate "
                    "with an explicit label like 'FLAG FOUND: ...'.",
                    "For large inputs or many variants, score bounded samples first, keep "
                    "only the best few, and run full recovery on finalists.",
                    "Challenge files are copied from /home/ctfplayer/ctf_files by default.",
                ]
            )
        return rules

    @staticmethod
    def _script_correction_instruction(failure_kind: object) -> str:
        base = (
            "The previous script attempt failed or produced no flag. "
            "Analyze the error below and write a CORRECTED script. "
            "Do NOT repeat the same approach without fixing the issue. "
        )
        if str(failure_kind or "") in {"network_pipe_closed", "connection_reset", "connection_refused"}:
            return (
                base
                + "Treat this as a protocol or availability failure, not proof that the "
                "algorithm is wrong. Use a small stdlib-only network harness with "
                "connect/read timeouts <=5 seconds and an overall deadline <=45 seconds. "
                "Print the exact connection state and stop cleanly if the endpoint is "
                "unavailable."
            )
        if str(failure_kind or "") in {"timeout", "unbounded_loop_guard"}:
            return (
                base
                + "Replace unbounded iteration with fast-forward logic, bounded sampling, "
                "or a smaller diagnostic harness. Do not reuse the same oversized value "
                "as a loop bound unless fresh evidence proves it is safe. Score bounded "
                "samples first and run full recovery only on finalists. If using "
                "signal.alarm, subprocess timeouts, or socket deadlines, set them below "
                "the tool timeout so the script exits cleanly and preserves diagnostics."
            )
        if str(failure_kind or "") == "syntax_error":
            return (
                base
                + "Fix syntax before changing the algorithm. Rewrite the script as a "
                "small complete program with helper functions, a main() function, and "
                "if __name__ == '__main__': raise SystemExit(main()). Do not use return "
                "outside a function, break/continue outside loops, or pasted fragments "
                "that would fail ast.parse. Keep the grounded algorithm and print a "
                "short diagnostic proving the corrected script ran."
            )
        if str(failure_kind or "") == "bytes_text_mismatch":
            return (
                base
                + "Fix the binary data model before changing the algorithm. Open files "
                "with rb/wb, keep ciphertext/plaintext/key material as bytes, use bytes "
                "literals and bytes.fromhex()/bytes.hex(), and write XOR helpers that "
                "handle Python 3 byte iteration as integers. Add a small self-test for "
                "the helper before processing full artifacts."
            )
        if str(failure_kind or "") == "path_type_mismatch":
            return (
                base
                + "Fix path handling before changing the algorithm. Use pathlib.Path "
                "consistently when using the / operator, converting roots with Path(...), "
                "or use os.path.join consistently for string paths. Add a tiny path "
                "construction self-test that checks the target exists or prints the "
                "resolved path before processing full artifacts."
            )
        if str(failure_kind or "") == "undefined_name":
            return (
                base
                + "Fix the undefined name before changing the algorithm. Do not leave "
                "placeholder variables from pseudocode or prior notebook cells. Bind every "
                "name from current evidence, todo context, environment variables, or values "
                "computed earlier in the same script. Add a small preflight section that "
                "prints the concrete paths, offsets, host/port, and function names the "
                "script will use."
            )
        if str(failure_kind or "") == "type_error":
            return (
                base
                + "Fix the Python type mismatch before changing the algorithm. Inspect the "
                "exact traceback line, print type()/repr() for the operands on a tiny sample, "
                "and convert deliberately between int, bytes, str, tuple/list, set, and Path. "
                "Avoid using | unless both operands are known-compatible set/dict/typing "
                "objects; for bit operations, ensure both operands are ints."
            )
        if str(failure_kind or "") == "no_candidate":
            return (
                base
                + "Enumerate bounded interpretations already present in todo context, "
                "knowledge hints, or stdout; score outputs by expected shape and "
                "printability; print the best candidates plus why each failed. Search "
                "the full recovered output for canonical brace flags and long bare CTF "
                "tokens before printing a preview. If the recovered output is a "
                "derived artifact, regenerate or read it in this same script and "
                "inspect it with format-appropriate semantics. Do not stop after a "
                "low-quality possible flag."
            )
        if str(failure_kind or "") == "near_miss":
            return (
                base
                + "Treat the previous output as useful but incomplete. Continue from "
                "the observed bytes/text/artifact shape instead of repeating discovery. "
                "If a file, image, barcode, QR code, or hidden-data container was "
                "recovered, inspect it with installed tools or stdlib parsing, extract "
                "embedded text/metadata/strings, and then search the complete recovered "
                "content for valid CTF candidates."
            )
        if str(failure_kind or "") == "parse_error":
            return (
                base
                + "Keep the same grounded algorithm, but fix input/output parsing. "
                "Derive an exact parser from observed stdout and source/protocol facts, "
                "accept only the expected value shape, and ignore prompt labels, banners, "
                "diagnostic lines, or echoed text that merely share a prefix. Add a small "
                "self-test with representative raw fragments before processing the full data."
            )
        if str(failure_kind or "") == "binary_structure_error":
            return (
                base
                + "Keep the same artifact and recovery path, but fix binary structure "
                "parsing. Before every struct.unpack/unpack_from or slice-derived header, "
                "check that offset + header_size <= len(data), validate magic bytes and "
                "declared lengths, and skip malformed/truncated candidates instead of "
                "crashing. Print the surviving offsets, file names, and byte ranges so the "
                "next step can continue from concrete recovered artifacts."
            )
        if str(failure_kind or "") == "scope_violation_blocked":
            return (
                base
                + "Remove the scope violation before changing the algorithm. For script.exec, "
                "set root = Path(os.environ.get('CTF_FILES_ROOT', '.')).resolve() and read or "
                "write only relative paths under that root. Use CTF_TEMP_DIR or tempfile for "
                "scratch files; do not hard-code /tmp. Do not scan /home, /root, /etc, /var, "
                "/opt, or shell startup files. If you need to inspect recovered data, inspect "
                "bytes already held in memory or files generated under CTF_FILES_ROOT in the same "
                "tool call."
            )
        if str(failure_kind or "") == "scratch_space_exhausted":
            return (
                base
                + "The previous attempt filled or could not create scratch space. Remove any "
                "hard-coded /tmp paths, use CTF_TEMP_DIR or tempfile for temporary files, keep "
                "large artifacts in memory when practical, write only needed generated artifacts "
                "under CTF_FILES_ROOT during the same call, and cap carving/extraction loops to "
                "the few best candidates."
            )
        return base

    @abstractmethod
    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        """Execute a todo against the current shared state."""


__all__ = [
    "WorkerAgent",
]
