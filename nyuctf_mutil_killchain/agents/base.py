"""Base abstraction for orchestrator-managed workers."""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import Any, TypeVar
from urllib.parse import urlparse

from pydantic import BaseModel

from nyuctf_mutil_killchain.llm import LLMClient, LLMClientError
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
ModelT = TypeVar("ModelT", bound=BaseModel)


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


def build_web_content_task(asset_id: str, base_url: str, *, priority: int = 79) -> Task:
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


def build_web_form_probe_task(
    *,
    asset_id: str,
    page_url: str,
    forms: list[dict[str, Any]],
    priority: int = 81,
) -> Task:
    """Build a deterministic follow-up task for interacting with discovered web forms."""

    normalized_forms = [form for form in forms if isinstance(form, dict)][:8]
    signatures: list[str] = []
    for form in normalized_forms[:4]:
        action = str(form.get("action") or "").strip()
        method = str(form.get("method") or "").strip().lower()
        field_names = [
            str(field.get("name") or "").strip()
            for field in list(form.get("inputs") or [])[:8]
            if isinstance(field, dict)
        ]
        signatures.append("|".join([action, method, ",".join(name for name in field_names if name)]))

    return Task(
        title=f"Interact with discovered forms for {asset_id}",
        description=(
            "Submit grounded baseline requests to discovered HTML forms, including file uploads when present, "
            "and capture reflected content, workflow changes, or flag candidates."
        ),
        task_type="web.form_probe",
        priority=priority,
        input_context={
            "asset_id": asset_id,
            "page_url": page_url,
            "forms": normalized_forms,
        },
        dedupe_key=f"web-form-probe:{asset_id}:{page_url}:{';'.join(signatures[:4])}",
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
    routing_intent: str | None = None,
    preferred_workers: list[str] | None = None,
    exclude_workers: list[str] | None = None,
    routing_notes: list[str] | None = None,
    priority: int = 82,
) -> Task:
    """Build a deterministic follow-up task for source/web file review."""

    input_context: dict[str, Any] = {
        "files_root": files_root,
        "source_files": source_files,
    }
    metadata: dict[str, Any] = {"planned_by": "worker-followup"}
    dedupe_parts = ["artifact-source-review", *source_files[:8]]
    if routing_intent:
        input_context["routing_intent"] = routing_intent
        metadata["routing_intent"] = routing_intent
        dedupe_parts.append(routing_intent)
    if preferred_workers:
        metadata["preferred_workers"] = preferred_workers[:6]
        dedupe_parts.extend(preferred_workers[:3])
    if exclude_workers:
        metadata["exclude_workers"] = exclude_workers[:8]
        dedupe_parts.extend(exclude_workers[:4])
    if routing_notes:
        metadata["routing_notes"] = routing_notes[:6]

    return Task(
        title="Review source artifacts",
        description="Inspect bundled source files for routes, secrets, and flag-like tokens.",
        task_type="artifact.source_review",
        priority=priority,
        input_context=input_context,
        dedupe_key=":".join(dedupe_parts),
        metadata=metadata,
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


def build_artifact_deep_review_task(
    *,
    files_root: str,
    analysis_kind: str,
    context_field: str,
    items: list[str],
    priority: int = 80,
) -> Task:
    """Build a routed deep-review task for one artifact bucket."""

    normalized_items = [item for item in items if item][:12]
    return Task(
        title=f"Deep review {analysis_kind} artifacts",
        description=(
            "Select the most appropriate artifact-review worker for this bundle and extract "
            "flag candidates, credentials, or pivot hints."
        ),
        task_type="artifact.deep_review",
        priority=priority,
        input_context={
            "files_root": files_root,
            "analysis_kind": analysis_kind,
            context_field: normalized_items,
        },
        dedupe_key=f"artifact-deep-review:{analysis_kind}:{','.join(normalized_items[:8])}",
        metadata={
            "planned_by": "worker-followup",
            "analysis_kind": analysis_kind,
            "analysis_field": context_field,
        },
    )


def build_credential_hunt_task(
    *,
    files_root: str,
    seed_terms: list[str] | None = None,
    priority: int = 90,
) -> Task:
    """Build a deterministic follow-up task for CTF credential harvesting."""

    normalized_seed_terms = merge_unique_strings(seed_terms, limit=12)
    dedupe_parts = ["credential-hunt", files_root]
    if normalized_seed_terms:
        dedupe_parts.extend(normalized_seed_terms[:6])
    return Task(
        title="Harvest candidate credentials",
        description=(
            "Search bundled challenge artifacts for usernames, passwords, bearer tokens, "
            "cookies, and other credential material that can unlock the next CTF pivot."
        ),
        task_type="credential.hunt",
        priority=priority,
        input_context={
            "files_root": files_root,
            "seed_terms": normalized_seed_terms,
        },
        dedupe_key=":".join(dedupe_parts),
        metadata={"planned_by": "worker-followup"},
    )


def build_flag_hunt_task(
    *,
    files_root: str,
    seed_terms: list[str] | None = None,
    priority: int = 96,
) -> Task:
    """Build a deterministic follow-up task for CTF-wide flag harvesting."""

    normalized_seed_terms = merge_unique_strings(seed_terms, limit=12)
    dedupe_parts = ["flag-hunt", files_root]
    if normalized_seed_terms:
        dedupe_parts.extend(normalized_seed_terms[:6])
    return Task(
        title="Hunt for concrete flag candidates",
        description=(
            "Search across bundled challenge artifacts for grounded flag candidates, "
            "decoder breadcrumbs, and flag-bearing paths."
        ),
        task_type="flag.hunt",
        priority=priority,
        input_context={
            "files_root": files_root,
            "seed_terms": normalized_seed_terms,
        },
        dedupe_key=":".join(dedupe_parts),
        metadata={"planned_by": "worker-followup"},
    )


def build_exploit_hypothesis_task(
    *,
    files_root: str | None = None,
    focus_asset_ids: list[str] | None = None,
    seed_terms: list[str] | None = None,
    priority: int = 76,
) -> Task:
    """Build a deterministic follow-up task for CTF exploit/pivot reasoning."""

    normalized_assets = merge_unique_strings(focus_asset_ids, limit=8)
    normalized_seed_terms = merge_unique_strings(seed_terms, limit=12)
    dedupe_parts = ["exploit-hypothesis"]
    if normalized_assets:
        dedupe_parts.extend(normalized_assets[:4])
    if normalized_seed_terms:
        dedupe_parts.extend(normalized_seed_terms[:4])
    return Task(
        title="Synthesize CTF exploit hypotheses",
        description=(
            "Use the accumulated evidence to prioritize the shortest path toward credential reuse, "
            "reachable secrets, and concrete flag recovery."
        ),
        task_type="exploit.hypothesis",
        priority=priority,
        input_context={
            "files_root": files_root,
            "focus_asset_ids": normalized_assets,
            "seed_terms": normalized_seed_terms,
        },
        dedupe_key=":".join(dedupe_parts),
        metadata={"planned_by": "worker-followup"},
    )


def build_credential_test_task(
    *,
    asset_id: str,
    base_url: str,
    credential_ids: list[str],
    seed_paths: list[str] | None = None,
    priority: int = 85,
) -> Task:
    """Build a deterministic follow-up task for credential reuse against a web target."""

    normalized_credential_ids = merge_unique_strings(credential_ids, limit=8)
    normalized_seed_paths = normalize_probe_paths(seed_paths, limit=16)
    return Task(
        title=f"Test recovered credentials against {asset_id}",
        description=(
            "Reuse recovered usernames, passwords, tokens, and cookies against the live challenge "
            "application to unlock privileged routes or direct flag access."
        ),
        task_type="exploit.credential_test",
        priority=priority,
        input_context={
            "asset_id": asset_id,
            "base_url": base_url,
            "credential_ids": normalized_credential_ids,
            "seed_paths": normalized_seed_paths,
        },
        dedupe_key=f"exploit-credential-test:{asset_id}:{','.join(normalized_credential_ids[:6])}",
        metadata={"planned_by": "worker-followup"},
    )


def build_cve_probe_task(
    *,
    asset_id: str,
    base_url: str | None = None,
    hostname: str | None = None,
    ports: list[int] | None = None,
    credential_ids: list[str] | None = None,
    seed_paths: list[str] | None = None,
    priority: int = 78,
) -> Task:
    """Build a deterministic follow-up task for targeted web/pwn exploit probing."""

    normalized_ports = sorted({int(port) for port in (ports or []) if int(port) > 0})[:16]
    normalized_credentials = merge_unique_strings(credential_ids, limit=8)
    normalized_seed_paths = normalize_probe_paths(seed_paths, limit=16)
    dedupe_seed_paths = sorted(normalized_seed_paths)
    target_label = base_url or hostname or asset_id
    return Task(
        title=f"Probe targeted exploit paths for {asset_id}",
        description=(
            "Attempt grounded web or TCP interactions against the authorized challenge target "
            "using recovered routes, prompts, and credentials."
        ),
        task_type="exploit.cve_probe",
        priority=priority,
        input_context={
            "asset_id": asset_id,
            "base_url": base_url,
            "hostname": hostname,
            "ports": normalized_ports,
            "credential_ids": normalized_credentials,
            "seed_paths": normalized_seed_paths,
        },
        dedupe_key=(
            f"exploit-cve-probe:{asset_id}:{target_label}:"
            f"{','.join(str(port) for port in normalized_ports[:6])}:"
            f"{','.join(normalized_credentials[:4])}:"
            f"{','.join(dedupe_seed_paths[:6])}"
        ),
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

    normalized_paths = normalize_probe_paths(paths, limit=20)
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


def _try_decode_blob(blob: str) -> list[str]:
    """Attempt common CTF encodings on a blob and return any flag-like results."""
    decoded: list[str] = []
    stripped = blob.strip()
    if not stripped or len(stripped) < 8:
        return decoded

    # Base64
    if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", stripped):
        for variant in (stripped, stripped + "=", stripped + "=="):
            try:
                raw = base64.b64decode(variant, validate=True)
                text = raw.decode("utf-8", errors="ignore")
                if FLAG_PATTERN.search(text):
                    decoded.extend(FLAG_PATTERN.findall(text))
            except Exception:
                pass

    # Hex
    if re.fullmatch(r"[0-9a-fA-F]{16,}", stripped) and len(stripped) % 2 == 0:
        try:
            raw = binascii.unhexlify(stripped)
            text = raw.decode("utf-8", errors="ignore")
            if FLAG_PATTERN.search(text):
                decoded.extend(FLAG_PATTERN.findall(text))
        except Exception:
            pass

    # ROT13
    try:
        text = codecs.decode(stripped, "rot_13")
        if FLAG_PATTERN.search(text) and not FLAG_PATTERN.search(stripped):
            decoded.extend(FLAG_PATTERN.findall(text))
    except Exception:
        pass

    return decoded


_BASE64_BLOB_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")
_HEX_BLOB_PATTERN = re.compile(r"(?:0x)?([0-9a-fA-F]{20,})")


def _looks_like_plausible_flag(candidate: str) -> bool:
    """Filter out obvious garbage from flag candidate extraction.

    Real flags are printable ASCII with only minimal control chars.
    Garbage like ``boo{xFpd]=}`` or ``A{h;~chPtf`m}`` can slip through
    the raw regex but fail basic plausibility checks.
    """
    if not candidate or len(candidate) < 4:
        return False
    prefix, _, body = candidate.partition("{")
    if not body or not body.endswith("}"):
        return False
    body = body[:-1]
    if not prefix.isalnum() and not all(c.isalnum() or c == "_" for c in prefix):
        return False
    if len(prefix) < 2:
        return False
    printable_count = sum(1 for ch in body if 32 <= ord(ch) <= 126)
    if not body or printable_count / len(body) < 0.90:
        return False
    control_count = sum(1 for ch in body if ord(ch) < 32 or ord(ch) == 127)
    if control_count > 0:
        return False
    return True


def extract_flag_candidates(*values: str | None) -> list[str]:
    """Extract unique flag-like tokens from the supplied strings.

    In addition to direct regex matches, attempts base64, hex, and ROT13
    decoding on long encoded-looking blobs.  Applies plausibility filtering
    to reject garbage matches that slip through the raw regex.
    """

    candidates: list[str] = []
    for value in values:
        if not value:
            continue
        for match in FLAG_PATTERN.findall(value):
            if match not in candidates and _looks_like_plausible_flag(match):
                candidates.append(match)
        for blob in _BASE64_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                if decoded not in candidates and _looks_like_plausible_flag(decoded):
                    candidates.append(decoded)
        for blob in _HEX_BLOB_PATTERN.findall(value):
            for decoded in _try_decode_blob(blob):
                if decoded not in candidates and _looks_like_plausible_flag(decoded):
                    candidates.append(decoded)
    return candidates


def merge_unique_strings(*groups: Iterable[str] | None, limit: int | None = None) -> list[str]:
    """Merge string groups while preserving order and removing empties."""

    merged: list[str] = []
    for group in groups:
        if not group:
            continue
        for item in group:
            text = str(item).strip()
            if not text or text in merged:
                continue
            merged.append(text)
            if limit is not None and len(merged) >= limit:
                return merged
    return merged


def normalize_probe_paths(paths: Iterable[str] | None, *, limit: int = 20) -> list[str]:
    """Normalize worker-discovered paths into forms suitable for web.path_probe tasks."""

    normalized: list[str] = []
    for raw_path in paths or ():
        text = str(raw_path).strip()
        if not text:
            continue

        if text.startswith(("http://", "https://")):
            parsed = urlparse(text)
            text = parsed.path or "/"
            if parsed.query:
                text = f"{text}?{parsed.query}"
        else:
            if any(character.isspace() for character in text):
                continue
            if not text.startswith("/"):
                if "/" in text or any(
                    token in text.lower()
                    for token in ("admin", "api", "debug", "flag", "login", "upload", "cgi-bin")
                ):
                    text = f"/{text.lstrip('/')}"
                else:
                    continue

        if any(character.isspace() for character in text):
            continue

        if text not in normalized:
            normalized.append(text)
        if len(normalized) >= limit:
            break
    return normalized


def build_path_probe_tasks_for_assets(
    state: GlobalState,
    paths: Iterable[str] | None,
    *,
    priority: int = 73,
) -> list[Task]:
    """Create deterministic path-probe tasks for every known web asset."""

    normalized_paths = normalize_probe_paths(paths, limit=20)
    if not normalized_paths:
        return []

    tasks: list[Task] = []
    for asset in state.assets.values():
        if not asset.base_url:
            continue
        tasks.append(
            build_http_path_probe_task(
                asset_id=asset.asset_id,
                base_url=asset.base_url,
                paths=normalized_paths,
                priority=priority,
            )
        )
    return tasks


def infer_web_context(
    task: Task,
    state: GlobalState,
) -> tuple[str | None, str | None]:
    """Resolve (asset_id, base_url) from task context and state.

    Only performs deterministic lookups:
    - Both present: return as-is.
    - asset_id given: look up base_url from that specific asset.
    - base_url given: find the exact-matching asset.
    - Neither present: return (None, None). Does NOT guess.
    """
    asset_id = task.input_context.get("asset_id")
    base_url = task.input_context.get("base_url")

    if asset_id and base_url:
        return asset_id, base_url

    if asset_id and not base_url:
        asset = state.assets.get(asset_id)
        if asset is not None and asset.base_url:
            return asset_id, asset.base_url

    if base_url and not asset_id:
        for asset in state.assets.values():
            if asset.base_url == base_url:
                return asset.asset_id, base_url

    return asset_id, base_url


def infer_host_context(
    task: Task,
    state: GlobalState,
) -> tuple[str | None, str | None]:
    """Resolve (asset_id, hostname) from task context and state.

    Only performs deterministic lookups. Does NOT iterate all assets
    as a wildcard fallback when both fields are missing.
    """
    asset_id = task.input_context.get("asset_id")
    hostname = task.input_context.get("hostname")

    if asset_id and hostname:
        return asset_id, hostname

    if asset_id and not hostname:
        asset = state.assets.get(asset_id)
        if asset is not None and asset.hostname:
            return asset_id, asset.hostname

    if hostname and not asset_id:
        for asset in state.assets.values():
            if asset.hostname == hostname:
                return asset.asset_id, hostname

    return asset_id, hostname


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
        """Minimal deterministic fallback score — LLM routing is preferred."""

        score = 50
        if task.task_type in self.supported_task_types:
            score += 30
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
