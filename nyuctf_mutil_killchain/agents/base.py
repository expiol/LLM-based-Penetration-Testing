"""Base abstraction for orchestrator-managed worker agents.

This module owns the :class:`WorkerAgent` abstract base class and the two
template subclasses (:class:`ToolBackedWorker`, :class:`ReasoningOnlyWorker`)
that share the dispatch pattern.  Helpers for flag extraction, network context,
and string normalization live in :mod:`nyuctf_mutil_killchain.agents._helpers`.
Task constructors live in :mod:`nyuctf_mutil_killchain.state.task_factory`.

The bottom of this module re-exports those helpers for backwards
compatibility with existing worker imports.  Once all workers have been
migrated to the per-stage modules, the shim can be removed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel

from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
from nyuctf_mutil_killchain.state import GlobalState, Task, TaskErrorCode, WorkerReport
from nyuctf_mutil_killchain.tools import ExecutionPlane, ToolExecutionError, ToolExecutionRequest

ModelT = TypeVar("ModelT", bound=BaseModel)


# ===========================================================================
# WorkerAgent — abstract base
# ===========================================================================


class WorkerAgent(ABC):
    """Abstract worker that can handle one or more task types."""

    name: str
    supported_task_types: tuple[str, ...]
    routing_summary: str = ""
    preferred_challenge_categories: tuple[str, ...] = ()
    required_context_keys: tuple[str, ...] = ()

    def __init__(
        self,
        *,
        llm_client: LLMClient | None = None,
        execution_plane: ExecutionPlane | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.execution_plane = execution_plane

    def supports(self, task: Task) -> bool:
        return any(task.task_type.startswith(prefix) for prefix in self.supported_task_types)

    def can_route_task(self, task: Task, state: GlobalState) -> tuple[bool, str | None]:
        """Return whether the worker is eligible for a routed dispatch."""

        del state
        if not self.supports(task):
            return False, "task type not supported"

        excluded = {
            str(value)
            for value in (
                list(task.metadata.get("exclude_workers") or [])
                + list(task.input_context.get("exclude_workers") or [])
            )
        }
        if self.name in excluded:
            return False, "worker explicitly excluded by task metadata"

        for key in self.required_context_keys:
            value = task.input_context.get(key)
            if value in (None, "", [], {}, ()):
                return False, f"missing required context key: {key}"
        return True, None

    def routing_score(self, task: Task, state: GlobalState) -> int:
        """Minimal deterministic score exposed as context for LLM routing."""

        score = 50
        if task.task_type in self.supported_task_types:
            score += 30
        category = str(state.metadata.get("challenge", {}).get("category") or "").lower()
        if category and category in self.preferred_challenge_categories:
            score += 25
        return score

    def routing_profile(self, task: Task, state: GlobalState) -> dict[str, Any]:
        """Return structured metadata for LLM-assisted worker routing."""

        default_summary = (self.__doc__ or "").strip().splitlines()
        return {
            "worker_name": self.name,
            "supported_task_types": list(self.supported_task_types),
            "routing_summary": self.routing_summary or (default_summary[0] if default_summary else self.name),
            "preferred_challenge_categories": list(self.preferred_challenge_categories),
            "required_context_keys": list(self.required_context_keys),
            "heuristic_score": self.routing_score(task, state),
        }

    def generate_structured_output(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        schema: type[ModelT],
        temperature: float = 0.2,
    ) -> ModelT:
        """Call llm_client.generate_json and return the validated result.

        Raises LLMClientError if the LLM client is not configured or the call fails.
        """

        if self.llm_client is None:
            raise LLMClientError(
                f"{type(self).__name__} requires an LLM client but none was provided."
            )

        return self.llm_client.generate_json(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            schema=schema,
            temperature=temperature,
        )

    @abstractmethod
    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        """Execute a task against the current shared state."""


# ===========================================================================
# ToolBackedWorker — generic plugin-dispatch template
# ===========================================================================


class ToolStep(BaseModel):
    """One :class:`ToolBackedWorker` recipe: how to translate a task into a tool call.

    A subclass declares ``dispatch: dict[task_type, ToolStep]`` and the base
    ``run()`` implementation handles the full pipeline:

      1. Build ``ToolExecutionRequest`` from ``request_metadata``.
      2. Execute through ``execution_plane``.
      3. Optionally call ``synthesize`` to merge LLM guidance into the result.
      4. Optionally call ``followups`` to construct new tasks.

    The ``synthesize`` and ``followups`` callables are imported lazily by each
    worker subclass — they live in :mod:`agents.reasoning` (LLM glue) or in
    the worker module itself (deterministic post-processing).
    """

    model_config = {"arbitrary_types_allowed": True}

    tool_name: str
    parser_name: str = "jsonl_signals"
    timeout_s: int = 60
    label: str = ""

    request_metadata: Any  # Callable[[Task, GlobalState], dict[str, Any]]
    synthesize: Any = None  # Callable[[WorkerAgent, GlobalState, Task, ToolExecutionBundle], tuple[BaseModel|None, list[str], dict[str, Any]]]
    followups: Any = None   # Callable[[WorkerAgent, GlobalState, Task, ToolExecutionBundle, dict, list[str]], list[Task]]


class ToolBackedWorker(WorkerAgent):
    """Worker that delegates the task body to a :class:`ToolStep` lookup.

    Subclasses declare:

    - ``name`` and ``supported_task_types`` (as for :class:`WorkerAgent`)
    - ``dispatch``: ``ClassVar[dict[str, ToolStep]]`` mapping task_type -> recipe
    - optionally override ``can_route_task``/``routing_score`` for per-step
      context requirements

    The base class handles validation, plugin dispatch, evidence wrapping,
    and follow-up task generation.
    """

    dispatch: ClassVar[dict[str, ToolStep]] = {}

    def supports(self, task: Task) -> bool:
        if task.task_type in self.dispatch:
            return True
        return super().supports(task)

    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        step = self.dispatch.get(task.task_type)
        if step is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} has no dispatch entry for task type {task.task_type!r}.",
                error=(
                    f"{type(self).__name__}.dispatch is missing an entry for {task.task_type!r}; "
                    "either add a ToolStep or revise the worker's supported_task_types."
                ),
                retryable=False,
            )

        if self.execution_plane is None:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"{self.name} requires an execution plane; none is configured.",
                error=(
                    f"{type(self).__name__}.execution_plane is None — "
                    f"register the {step.tool_name!r} plugin before dispatching {task.task_type!r}."
                ),
                retryable=False,
            )

        request = ToolExecutionRequest(
            tool_name=step.tool_name,
            parser_name=step.parser_name,
            timeout_s=int(task.input_context.get("timeout_s", step.timeout_s)),
            metadata=step.request_metadata(task, state),
        )

        try:
            bundle = self.execution_plane.execute(task.task_id, request)
        except ToolExecutionError as exc:
            return WorkerReport(
                task_id=task.task_id,
                worker_name=self.name,
                success=False,
                summary=f"{step.label or step.tool_name} execution failed.",
                error=str(exc),
            )

        worker_notes = list(bundle.parsed.notes)
        guidance: BaseModel | None = None
        flag_candidates: list[str] = list(bundle.parsed.output_context.get("flag_candidates") or [])
        output_context: dict[str, Any] = dict(bundle.parsed.output_context)

        if step.synthesize is not None:
            guidance, flag_candidates, output_context = step.synthesize(
                self, state, task, bundle,
            )

        if step.followups is not None:
            new_tasks = step.followups(self, state, task, bundle, output_context, flag_candidates)
        else:
            from nyuctf_mutil_killchain.state.task_factory import build_flag_validation_task

            new_tasks = [
                build_flag_validation_task(candidate, source=step.tool_name)
                for candidate in flag_candidates
            ]

        return WorkerReport(
            task_id=task.task_id,
            worker_name=self.name,
            success=True,
            summary=bundle.parsed.summary,
            output_context=output_context,
            asset_updates=list(bundle.parsed.asset_updates),
            finding_updates=list(bundle.parsed.finding_updates),
            credential_updates=list(bundle.parsed.credential_updates),
            network_updates=list(bundle.parsed.network_updates),
            evidence_updates=[bundle.evidence],
            new_tasks=new_tasks,
            notes=worker_notes + [f"{self.name} ran {step.label or step.tool_name}."],
        )


# ===========================================================================
# ReasoningOnlyWorker — LLM-only stage worker (no plugin dispatch)
# ===========================================================================


class ReasoningOnlyWorker(WorkerAgent):
    """Worker that produces a :class:`WorkerReport` from LLM reasoning alone.

    For tasks that have no concrete plugin to call (such as
    ``exploit.hypothesis`` or ``flag.validate``), the subclass implements a
    single ``_reason(task, state)`` method that returns a guidance object plus
    the report fields it should drive.
    """

    @abstractmethod
    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        """Subclasses still implement run; this base just documents intent."""


# ===========================================================================
# Backwards-compat re-exports
# ===========================================================================
# Existing worker modules and tests import helpers from agents.base.
# The canonical homes are:
#   - agents._helpers.network    network/web context inference
#   - agents._helpers.flag       flag extraction / decoding
#   - agents._helpers.strings    string/list normalization
#   - state.task_factory         build_*_task constructors

from nyuctf_mutil_killchain.agents._helpers.flag import (  # noqa: E402, F401
    extract_flag_candidates,
)
from nyuctf_mutil_killchain.agents._helpers.network import (  # noqa: E402, F401
    AMBIGUOUS_WEB_SERVICE_NAMES,
    COMMON_WEB_PORTS,
    DEFAULT_WEB_PORTS,
    TLS_WEB_PORTS,
    WEB_SERVICE_NAMES,
    WEB_SERVICE_TOKENS,
    banner_looks_like_http,
    infer_host_context,
    infer_web_context,
    infer_web_scheme,
    infer_web_urls,
    infer_web_urls_from_banners,
    service_looks_like_web,
)
from nyuctf_mutil_killchain.agents._helpers.strings import (  # noqa: E402, F401
    merge_unique_strings,
    normalize_probe_paths,
)
from nyuctf_mutil_killchain.state.task_factory import (  # noqa: E402, F401
    build_archive_triage_task,
    build_artifact_deep_review_task,
    build_binary_triage_task,
    build_computation_analysis_task,
    build_credential_hunt_task,
    build_credential_test_task,
    build_cve_probe_task,
    build_exploit_hypothesis_task,
    build_flag_hunt_task,
    build_flag_validation_task,
    build_http_path_probe_task,
    build_path_probe_tasks_for_assets,
    build_pcap_review_task,
    build_repo_review_task,
    build_runtime_probe_task,
    build_service_banner_task,
    build_source_review_task,
    build_sqlite_review_task,
    build_web_content_task,
    build_web_form_probe_task,
    build_web_review_task,
)

__all__ = [
    "ReasoningOnlyWorker",
    "ToolBackedWorker",
    "ToolStep",
    "WorkerAgent",
    # Helpers (re-exported for backwards compatibility)
    "AMBIGUOUS_WEB_SERVICE_NAMES",
    "COMMON_WEB_PORTS",
    "DEFAULT_WEB_PORTS",
    "TLS_WEB_PORTS",
    "WEB_SERVICE_NAMES",
    "WEB_SERVICE_TOKENS",
    "banner_looks_like_http",
    "build_archive_triage_task",
    "build_artifact_deep_review_task",
    "build_binary_triage_task",
    "build_computation_analysis_task",
    "build_credential_hunt_task",
    "build_credential_test_task",
    "build_cve_probe_task",
    "build_exploit_hypothesis_task",
    "build_flag_hunt_task",
    "build_flag_validation_task",
    "build_http_path_probe_task",
    "build_path_probe_tasks_for_assets",
    "build_pcap_review_task",
    "build_repo_review_task",
    "build_runtime_probe_task",
    "build_service_banner_task",
    "build_source_review_task",
    "build_sqlite_review_task",
    "build_web_content_task",
    "build_web_form_probe_task",
    "build_web_review_task",
    "extract_flag_candidates",
    "infer_host_context",
    "infer_web_context",
    "infer_web_scheme",
    "infer_web_urls",
    "infer_web_urls_from_banners",
    "merge_unique_strings",
    "normalize_probe_paths",
    "service_looks_like_web",
]
