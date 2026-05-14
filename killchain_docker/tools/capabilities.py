"""Capability-level adapter over concrete execution plugins.

Workers should ask for a capability such as ``http.probe_paths`` or
``binary.execute``.  The gateway owns the mapping from that stable capability
name to the current plugin implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from killchain_docker.tools.core import (
    ExecutionPlane,
    ToolExecutionBundle,
    ToolExecutionRequest,
)


class ToolCapability(StrEnum):
    HTTP_METADATA = "http.metadata"
    HTTP_CONTENT = "http.content"
    HTTP_FORM_PROBE = "http.form_probe"
    HTTP_PROBE_PATHS = "http.probe_paths"
    HOST_INVENTORY = "host.inventory"
    HOST_BANNER = "host.banner"
    VULN_SCAN = "vuln.scan"
    CREDENTIAL_HARVEST = "credential.harvest"
    CREDENTIAL_LOGIN = "credential.login"
    EXPLOIT_PROBE = "exploit.probe"
    FLAG_HARVEST = "flag.harvest"
    SCRIPT_EXECUTE = "script.execute"
    ARTIFACT_TRIAGE = "artifact.triage"
    ARTIFACT_ARCHIVE = "artifact.archive"
    ARTIFACT_SOURCE = "artifact.read_source"
    ARTIFACT_RUNTIME = "artifact.runtime"
    ARTIFACT_COMPUTATION = "artifact.computation"
    ARTIFACT_BINARY_TRIAGE = "binary.triage"
    ARTIFACT_BINARY_DISASSEMBLE = "binary.disassemble"
    ARTIFACT_BINARY_EXECUTE = "binary.execute"
    ARTIFACT_SQLITE = "artifact.sqlite"
    ARTIFACT_PCAP = "artifact.pcap"
    ARTIFACT_REPO = "artifact.repo"


def capability_source(capability: ToolCapability | str) -> str:
    """Stable provenance string for worker-produced follow-up tasks."""

    return ToolCapability(capability).value


@dataclass(frozen=True)
class ToolSpec:
    """Concrete plugin binding for one capability."""

    capability: ToolCapability
    tool_name: str
    parser_name: str = "jsonl_signals"
    default_timeout_s: int = 60


DEFAULT_TOOL_SPECS: dict[ToolCapability, ToolSpec] = {
    ToolCapability.HTTP_METADATA: ToolSpec(ToolCapability.HTTP_METADATA, "local_http_metadata", default_timeout_s=20),
    ToolCapability.HTTP_CONTENT: ToolSpec(ToolCapability.HTTP_CONTENT, "local_http_content", default_timeout_s=30),
    ToolCapability.HTTP_FORM_PROBE: ToolSpec(ToolCapability.HTTP_FORM_PROBE, "http_form_probe", default_timeout_s=90),
    ToolCapability.HTTP_PROBE_PATHS: ToolSpec(ToolCapability.HTTP_PROBE_PATHS, "http_path_probe", default_timeout_s=45),
    ToolCapability.HOST_INVENTORY: ToolSpec(ToolCapability.HOST_INVENTORY, "local_host_inventory", default_timeout_s=45),
    ToolCapability.HOST_BANNER: ToolSpec(ToolCapability.HOST_BANNER, "tcp_banner_probe", default_timeout_s=30),
    ToolCapability.VULN_SCAN: ToolSpec(ToolCapability.VULN_SCAN, "vuln_scan", default_timeout_s=90),
    ToolCapability.CREDENTIAL_HARVEST: ToolSpec(ToolCapability.CREDENTIAL_HARVEST, "credential_harvest", default_timeout_s=60),
    ToolCapability.CREDENTIAL_LOGIN: ToolSpec(ToolCapability.CREDENTIAL_LOGIN, "credential_login_probe", default_timeout_s=90),
    ToolCapability.EXPLOIT_PROBE: ToolSpec(ToolCapability.EXPLOIT_PROBE, "ctf_exploit_probe", default_timeout_s=120),
    ToolCapability.FLAG_HARVEST: ToolSpec(ToolCapability.FLAG_HARVEST, "flag_harvest", default_timeout_s=60),
    ToolCapability.SCRIPT_EXECUTE: ToolSpec(ToolCapability.SCRIPT_EXECUTE, "script_execution", default_timeout_s=70),
    ToolCapability.ARTIFACT_TRIAGE: ToolSpec(ToolCapability.ARTIFACT_TRIAGE, "artifact_triage", default_timeout_s=60),
    ToolCapability.ARTIFACT_ARCHIVE: ToolSpec(ToolCapability.ARTIFACT_ARCHIVE, "archive_triage", default_timeout_s=90),
    ToolCapability.ARTIFACT_SOURCE: ToolSpec(ToolCapability.ARTIFACT_SOURCE, "source_review", default_timeout_s=120),
    ToolCapability.ARTIFACT_RUNTIME: ToolSpec(ToolCapability.ARTIFACT_RUNTIME, "runtime_probe", default_timeout_s=60),
    ToolCapability.ARTIFACT_COMPUTATION: ToolSpec(ToolCapability.ARTIFACT_COMPUTATION, "computation_analysis", default_timeout_s=180),
    ToolCapability.ARTIFACT_BINARY_TRIAGE: ToolSpec(ToolCapability.ARTIFACT_BINARY_TRIAGE, "binary_triage", default_timeout_s=60),
    ToolCapability.ARTIFACT_BINARY_DISASSEMBLE: ToolSpec(ToolCapability.ARTIFACT_BINARY_DISASSEMBLE, "binary_disassembly", default_timeout_s=90),
    ToolCapability.ARTIFACT_BINARY_EXECUTE: ToolSpec(ToolCapability.ARTIFACT_BINARY_EXECUTE, "binary_run", default_timeout_s=120),
    ToolCapability.ARTIFACT_SQLITE: ToolSpec(ToolCapability.ARTIFACT_SQLITE, "sqlite_review", default_timeout_s=60),
    ToolCapability.ARTIFACT_PCAP: ToolSpec(ToolCapability.ARTIFACT_PCAP, "pcap_review", default_timeout_s=90),
    ToolCapability.ARTIFACT_REPO: ToolSpec(ToolCapability.ARTIFACT_REPO, "repo_review", default_timeout_s=90),
}


class ToolGateway:
    """Run stable capabilities through the current execution plane."""

    def __init__(
        self,
        execution_plane: ExecutionPlane,
        *,
        specs: dict[ToolCapability, ToolSpec] | None = None,
    ) -> None:
        self.execution_plane = execution_plane
        self.specs = dict(specs or DEFAULT_TOOL_SPECS)

    def run(
        self,
        *,
        task_id: str,
        capability: ToolCapability | str,
        metadata: dict[str, Any],
        timeout_s: int | None = None,
        parser_name: str | None = None,
        max_retries: int = 1,
    ) -> ToolExecutionBundle:
        cap = ToolCapability(capability)
        spec = self.specs[cap]
        request = ToolExecutionRequest(
            capability=cap.value,
            tool_name=spec.tool_name,
            parser_name=parser_name or spec.parser_name,
            timeout_s=timeout_s or spec.default_timeout_s,
            max_retries=max_retries,
            metadata=metadata,
        )
        return self.execution_plane.execute(task_id, request)
