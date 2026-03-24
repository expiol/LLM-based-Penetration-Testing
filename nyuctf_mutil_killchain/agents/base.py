"""Base abstraction for orchestrator-managed workers."""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from collections.abc import Iterable

from nyuctf_mutil_killchain.llm import LLMClient
from nyuctf_mutil_killchain.state import GlobalState, Service, Task, WorkerReport
from nyuctf_mutil_killchain.tools import ExecutionPlane

COMMON_WEB_PORTS = frozenset({80, 443, 8000, 8080, 8443, 8888, 3000, 5000, 5601, 9200})
DEFAULT_WEB_PORTS = frozenset({80, 443})
TLS_WEB_PORTS = frozenset({443, 8443})
WEB_SERVICE_NAMES = frozenset(
    {
        "http",
        "https",
        "http-proxy",
        "ssl/http",
        "sun-answerbook",
    }
)
AMBIGUOUS_WEB_SERVICE_NAMES = frozenset({"http-alt"})
WEB_SERVICE_TOKENS = (
    "apache",
    "caddy",
    "django",
    "express",
    "flask",
    "gunicorn",
    "http",
    "https",
    "iis",
    "jetty",
    "nginx",
    "tomcat",
    "uvicorn",
    "werkzeug",
    "web",
)
FLAG_PATTERN = re.compile(r"[A-Za-z0-9_]+\{[^{}\n]{4,200}\}")


def infer_web_urls(
    *,
    hostname: str | None,
    ip_address: str | None,
    services: Iterable[Service],
) -> list[str]:
    """Infer candidate web URLs from service fingerprints."""

    target_host = hostname or ip_address
    if not target_host:
        return []

    urls: list[str] = []
    for service in services:
        if not service_looks_like_web(service):
            continue

        scheme = infer_web_scheme(port=service.port, service_name=service.name)
        candidate = f"{scheme}://{target_host}:{service.port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


def service_looks_like_web(service: Service) -> bool:
    """Return True when service metadata is strong enough to justify HTTP probing."""

    service_name = (service.name or "").strip().lower()
    service_fingerprint = " ".join(
        part.strip().lower()
        for part in (service.name, service.product, service.version)
        if part
    )

    if service_name in WEB_SERVICE_NAMES:
        return True
    if (
        service_name in AMBIGUOUS_WEB_SERVICE_NAMES
        and not (service.product or "").strip()
        and not (service.version or "").strip()
        and service.port not in DEFAULT_WEB_PORTS
    ):
        return False
    if any(token in service_fingerprint for token in WEB_SERVICE_TOKENS):
        return True
    return service.port in DEFAULT_WEB_PORTS


def infer_web_scheme(*, port: int, service_name: str | None = None) -> str:
    """Infer the most likely HTTP scheme for a service."""

    normalized_name = (service_name or "").strip().lower()
    if normalized_name == "https" or port in TLS_WEB_PORTS:
        return "https"
    return "http"


def banner_looks_like_http(banner: str) -> bool:
    """Return True if a captured banner looks like an HTTP response."""

    text = banner.strip()
    if not text:
        return False

    lowered = text.lower()
    if text.startswith(("HTTP/1.", "HTTP/2", "HTTP/3")):
        return True
    if lowered.startswith("<!doctype html") or lowered.startswith("<html"):
        return True
    if "content-type:" in lowered and "server:" in lowered:
        return True
    return False


def infer_web_urls_from_banners(
    *,
    hostname: str | None,
    ip_address: str | None,
    banner_hits: dict[str, str] | None,
) -> list[str]:
    """Infer candidate web URLs from TCP banner captures."""

    target_host = hostname or ip_address
    if not target_host or not banner_hits:
        return []

    urls: list[str] = []
    for raw_port, banner in banner_hits.items():
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        if not banner_looks_like_http(str(banner)):
            continue

        scheme = infer_web_scheme(port=port)
        candidate = f"{scheme}://{target_host}:{port}"
        if candidate not in urls:
            urls.append(candidate)
    return urls


def build_web_review_task(asset_id: str, base_url: str, *, priority: int = 78) -> Task:
    """Build a deterministic follow-up task for web surface review."""

    return Task(
        title=f"Review web surface for {asset_id}",
        description="Collect HTTP metadata and create an evidence-based assessment note.",
        task_type="web.review_surface",
        priority=priority,
        input_context={"asset_id": asset_id, "base_url": base_url},
        dedupe_key=f"web-review:{asset_id}:{base_url}",
        metadata={"planned_by": "worker-followup"},
    )


def build_web_content_task(asset_id: str, base_url: str, *, priority: int = 72) -> Task:
    """Build a deterministic follow-up task for content-aware web review."""

    return Task(
        title=f"Review web content for {asset_id}",
        description="Fetch the response body, enumerate links/forms, and inspect content for exposed attack surface.",
        task_type="web.content_review",
        priority=priority,
        input_context={"asset_id": asset_id, "base_url": base_url},
        dedupe_key=f"web-content:{asset_id}:{base_url}",
        metadata={"planned_by": "worker-followup"},
    )


def build_binary_triage_task(
    *,
    files_root: str,
    binary_files: list[str],
    priority: int = 84,
) -> Task:
    """Build a deterministic follow-up task for binary artifact triage."""

    return Task(
        title="Inspect binary artifacts",
        description="Analyze bundled binaries for hardcoded strings, binary metadata, and obvious flag candidates.",
        task_type="artifact.binary_triage",
        priority=priority,
        input_context={
            "files_root": files_root,
            "binary_files": binary_files,
        },
        dedupe_key="artifact-binary-triage:" + ",".join(binary_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_archive_triage_task(
    *,
    files_root: str,
    archive_files: list[str],
    priority: int = 83,
) -> Task:
    """Build a deterministic follow-up task for archive inspection."""

    return Task(
        title="Inspect archive artifacts",
        description="Review bundled archives for hidden files, embedded sources, and flag-like content.",
        task_type="artifact.archive_triage",
        priority=priority,
        input_context={
            "files_root": files_root,
            "archive_files": archive_files,
        },
        dedupe_key="artifact-archive-triage:" + ",".join(archive_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_source_review_task(
    *,
    files_root: str,
    source_files: list[str],
    priority: int = 82,
) -> Task:
    """Build a deterministic follow-up task for source/web file review."""

    return Task(
        title="Review source artifacts",
        description="Inspect bundled source files for routes, secrets, and flag-like tokens.",
        task_type="artifact.source_review",
        priority=priority,
        input_context={
            "files_root": files_root,
            "source_files": source_files,
        },
        dedupe_key="artifact-source-review:" + ",".join(source_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_computation_analysis_task(
    *,
    files_root: str,
    source_files: list[str],
    priority: int = 83,
) -> Task:
    """Build a deterministic follow-up task for computation-heavy source analysis."""

    return Task(
        title="Analyze computation-heavy source artifacts",
        description=(
            "Execute bundled source files in the container, inspect arithmetic and transform "
            "pipelines, and recover concrete plaintext or flag candidates when possible."
        ),
        task_type="artifact.computation_analysis",
        priority=priority,
        input_context={
            "files_root": files_root,
            "source_files": source_files,
        },
        dedupe_key="artifact-computation-analysis:" + ",".join(source_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_runtime_probe_task(
    *,
    files_root: str,
    source_files: list[str],
    priority: int = 84,
) -> Task:
    """Build a deterministic follow-up task for executing bundled script artifacts."""

    return Task(
        title="Execute script-like source artifacts",
        description=(
            "Run bundled scripts with the appropriate interpreter inside the agent container, "
            "capture runtime output, and extract flag candidates or encoded blobs."
        ),
        task_type="artifact.runtime_probe",
        priority=priority,
        input_context={
            "files_root": files_root,
            "source_files": source_files,
        },
        dedupe_key="artifact-runtime-probe:" + ",".join(source_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_sqlite_review_task(
    *,
    files_root: str,
    database_files: list[str],
    priority: int = 81,
) -> Task:
    """Build a deterministic follow-up task for SQLite/database inspection."""

    return Task(
        title="Review SQLite artifacts",
        description="Inspect bundled SQLite databases for tables, rows, secrets, and flag-like tokens.",
        task_type="artifact.sqlite_review",
        priority=priority,
        input_context={
            "files_root": files_root,
            "database_files": database_files,
        },
        dedupe_key="artifact-sqlite-review:" + ",".join(database_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_pcap_review_task(
    *,
    files_root: str,
    pcap_files: list[str],
    priority: int = 80,
) -> Task:
    """Build a deterministic follow-up task for packet capture review."""

    return Task(
        title="Review packet captures",
        description="Inspect bundled PCAP artifacts for hosts, URLs, credentials, and flag-like content.",
        task_type="artifact.pcap_review",
        priority=priority,
        input_context={
            "files_root": files_root,
            "pcap_files": pcap_files,
        },
        dedupe_key="artifact-pcap-review:" + ",".join(pcap_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_repo_review_task(
    *,
    files_root: str,
    repo_paths: list[str],
    priority: int = 79,
) -> Task:
    """Build a deterministic follow-up task for embedded git repository review."""

    return Task(
        title="Review embedded repositories",
        description="Inspect bundled git repositories for interesting history, secrets, and flag-like tokens.",
        task_type="artifact.repo_review",
        priority=priority,
        input_context={
            "files_root": files_root,
            "repo_paths": repo_paths,
        },
        dedupe_key="artifact-repo-review:" + ",".join(repo_paths[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_flag_validation_task(
    candidate: str,
    *,
    source: str,
    priority: int = 99,
) -> Task:
    """Build a deterministic high-priority task for validating a candidate flag."""

    return Task(
        title="Validate candidate flag",
        description="Compare a discovered flag candidate against the expected challenge flag.",
        task_type="flag.validate",
        priority=priority,
        input_context={
            "candidate_flag": candidate,
            "candidate_source": source,
        },
        dedupe_key=f"flag-validate:{candidate}",
        metadata={"planned_by": "worker-followup"},
    )


def build_service_banner_task(
    *,
    asset_id: str,
    hostname: str,
    ports: list[int],
    priority: int = 74,
) -> Task:
    """Build a deterministic follow-up task for TCP banner collection."""

    normalized_ports = sorted({int(port) for port in ports if int(port) > 0})[:16]
    return Task(
        title=f"Collect service banners for {asset_id}",
        description="Connect to exposed ports and capture service banners or greeting text.",
        task_type="host.banner_grab",
        priority=priority,
        input_context={
            "asset_id": asset_id,
            "hostname": hostname,
            "ports": normalized_ports,
        },
        dedupe_key=f"host-banner:{asset_id}:{','.join(str(port) for port in normalized_ports)}",
        metadata={"planned_by": "worker-followup"},
    )


def build_http_path_probe_task(
    *,
    asset_id: str,
    base_url: str,
    paths: list[str],
    priority: int = 73,
) -> Task:
    """Build a deterministic follow-up task for probing interesting HTTP paths."""

    normalized_paths = list(dict.fromkeys(path for path in paths if path))[:20]
    return Task(
        title=f"Probe interesting paths for {asset_id}",
        description="Fetch interesting application paths discovered from source, links, or content review.",
        task_type="web.path_probe",
        priority=priority,
        input_context={
            "asset_id": asset_id,
            "base_url": base_url,
            "paths": normalized_paths,
        },
        dedupe_key=f"web-path-probe:{asset_id}:{base_url}:{','.join(normalized_paths[:8])}",
        metadata={"planned_by": "worker-followup"},
    )


def extract_flag_candidates(*values: str | None) -> list[str]:
    """Extract unique flag-like tokens from the supplied strings."""

    candidates: list[str] = []
    for value in values:
        if not value:
            continue
        for match in FLAG_PATTERN.findall(value):
            if match not in candidates:
                candidates.append(match)
    return candidates


class WorkerAgent(ABC):
    """Abstract worker that can handle one or more task types."""

    name: str
    supported_task_types: tuple[str, ...]

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

    @abstractmethod
    def run(self, task: Task, state: GlobalState) -> WorkerReport:
        """Execute a task against the current shared state."""
