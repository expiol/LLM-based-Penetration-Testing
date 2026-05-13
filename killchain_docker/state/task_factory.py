"""Deterministic task constructors used by workers and planners.

These factories assemble :class:`Task` instances with stable :attr:`Task.dedupe_key`
values so that worker follow-ups, planner proposals, and orchestrator repair all
converge on the same task identity.

The factories live in the ``state`` package because they depend only on
``state`` models, and both the agent layer (L3) and the orchestrator layer (L4)
need to construct tasks.  Keeping them here avoids the layering violation of
having task constructors in ``agents.base`` while orchestrator/planner imports
them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Any

from killchain_docker.state.models import GlobalState, Task


# ---------------------------------------------------------------------------
# Internal normalization helpers (kept here to avoid an L3 dependency)
# ---------------------------------------------------------------------------

def _merge_unique(*groups: Iterable[str] | None, limit: int | None = None) -> list[str]:
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


def _normalize_paths(paths: Iterable[str] | None, *, limit: int = 20) -> list[str]:
    from urllib.parse import urlparse

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
            if any(c.isspace() for c in text):
                continue
            if not text.startswith("/"):
                if "/" in text or any(
                    token in text.lower()
                    for token in ("admin", "api", "debug", "flag", "login", "upload", "cgi-bin")
                ):
                    text = f"/{text.lstrip('/')}"
                else:
                    continue

        if any(c.isspace() for c in text):
            continue

        if text not in normalized:
            normalized.append(text)
        if len(normalized) >= limit:
            break
    return normalized


# ---------------------------------------------------------------------------
# Web stage
# ---------------------------------------------------------------------------

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


def build_http_path_probe_task(
    *,
    asset_id: str,
    base_url: str,
    paths: list[str],
    priority: int = 73,
) -> Task:
    """Build a deterministic follow-up task for probing interesting HTTP paths."""

    normalized_paths = _normalize_paths(paths, limit=20)
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


def build_path_probe_tasks_for_assets(
    state: GlobalState,
    paths: Iterable[str] | None,
    *,
    priority: int = 73,
) -> list[Task]:
    """Create deterministic path-probe tasks for every known web asset."""

    normalized_paths = _normalize_paths(paths, limit=20)
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


# ---------------------------------------------------------------------------
# Host stage
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Artifact stage
# ---------------------------------------------------------------------------

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


def build_binary_disassembly_task(
    *,
    files_root: str,
    binary_files: list[str],
    priority: int = 82,
) -> Task:
    """Build a deterministic follow-up task for deep binary disassembly.

    Lower default priority than :func:`build_binary_triage_task` so triage
    (cheap) always runs first; this one only fires after triage failed to
    surface a flag candidate but the algorithm-in-binary signal is clearly
    needed (rev/pwn/crypto + a non-trivial ELF).
    """

    return Task(
        title="Disassemble binary artifacts",
        description=(
            "Run objdump-based disassembly on bundled binaries to recover "
            "per-function code, .rodata constants, and string xrefs that "
            "expose the embedded algorithm."
        ),
        task_type="artifact.binary_disassembly",
        priority=priority,
        input_context={
            "files_root": files_root,
            "binary_files": binary_files,
        },
        dedupe_key="artifact-binary-disassembly:" + ",".join(binary_files[:8]),
        metadata={"planned_by": "worker-followup"},
    )


def build_binary_run_task(
    *,
    files_root: str,
    binary_files: list[str],
    priority: int = 80,
) -> Task:
    """Build a deterministic follow-up task for sandboxed binary execution.

    Lowest of the three binary-stage priorities (84 triage → 82 disasm →
    80 run) so the cheap signal is exhausted first; this one fires last
    when neither strings nor disassembly produced a flag and the binary
    might *be* the oracle for its own algorithm (XOR cipher that is
    self-inverse, decoder toggled by an undocumented flag, etc.).
    """

    return Task(
        title="Run binary artifacts in a sandbox",
        description=(
            "Copy the bundled binary + challenge files into a /tmp working "
            "directory and try several invocations (no-args, --help, with "
            "each non-binary file positionally, stdin variants).  Capture "
            "stdout / stderr / new files for solver evidence."
        ),
        task_type="artifact.binary_run",
        priority=priority,
        input_context={
            "files_root": files_root,
            "binary_files": binary_files,
        },
        dedupe_key="artifact-binary-run:" + ",".join(binary_files[:8]),
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


# ---------------------------------------------------------------------------
# Credential / Flag stages
# ---------------------------------------------------------------------------

def build_credential_hunt_task(
    *,
    files_root: str,
    seed_terms: list[str] | None = None,
    priority: int = 90,
) -> Task:
    """Build a deterministic follow-up task for CTF credential harvesting."""

    normalized_seed_terms = _merge_unique(seed_terms, limit=12)
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

    normalized_seed_terms = _merge_unique(seed_terms, limit=12)
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


# Two acceptable flag shapes:
#
# 1. Canonical ``prefix{body}`` — every "standard" CTF flag (flag{...},
#    csaw{...}, key{...}).  Body is printable ASCII (incl. space) excluding
#    braces.  Prefix is ≥2 alnum/_ chars.  Single source of truth lives in
#    :mod:`state.constants`; we re-import the validator regex here.
# 2. Bare token — NYU dataset has a handful of non-standard challenges where
#    the flag is a single underscored/dashed identifier (e.g. CSAW 2013 stfu's
#    ``STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME``).  We require: starts alnum,
#    only alnum + ``_-.``, length 12-200, not a Python exception name.
from killchain_docker.state.constants import (  # noqa: E402
    FLAG_PREFIX_SHAPE as _FLAG_PREFIX_SHAPE,
    plausible_flag as _plausible_flag,
)

_FLAG_BARE_TOKEN_SHAPE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-.]{11,199}$")
_FLAG_PYTHON_EXCEPTION_RE = re.compile(
    r"^(?:[A-Z][A-Za-z0-9]*)+(?:Error|Exception|Warning)$"
)

# Even when the shape regex matches, these substrings betray echoed source code
# rather than a real answer (we saw the LLM solver write
# ``debug("flag{...}")`` style strings that then surfaced in stderr).  Also
# common LLM placeholders like ``test{test}`` that the placeholder filter in
# solver/parser.py already catches but other producers miss.
_FLAG_VALIDATION_SOURCE_NEEDLES: tuple[str, ...] = (
    "re.findall", "re.search", "re.match",
    "subprocess.", "os.system", "shell=true",
    "{thing}", "{tablename}", "{fieldname}",
    "{0}", "{1}", "{name}", "{flag}",
)

# Bare-token "give-up" sentinels that LLM solvers like to print when they
# can't recover the flag.  Matched as a case-insensitive substring (so
# e.g. ``NO_FLAG_FOUND_HERE`` and ``flag_not_recovered_v2`` both reject).
_FLAG_BARE_TOKEN_NOISE_NEEDLES: tuple[str, ...] = (
    "no_flag_found", "noflagfound",
    "flag_not_found", "flag_not_recovered",
    "no_flag_recovered",
    "manual_review_required", "manual_review",
    "todo_replace_me", "your_flag_here", "insert_flag",
    "placeholder", "not_implemented",
)


def is_validatable_flag_candidate(candidate: str) -> bool:
    """Cheap shape check: only call the validator on candidates that *could* be a flag.

    Accepts both canonical ``prefix{body}`` flags and NYU-style bare-token
    flags.  Anything else is debug log, traceback, or source-code echo, and
    short-circuiting those avoids burning an LLM-validation cycle on every
    junk line.
    """
    text = (candidate or "").strip()
    if _FLAG_PREFIX_SHAPE.fullmatch(text):
        low = text.lower()
        if any(needle in low for needle in _FLAG_VALIDATION_SOURCE_NEEDLES):
            return False
        # Also gate on the full plausibility filter so 1-char prefixes,
        # template-noise bodies (``flag{pagination}``) and CSS/format-spec
        # bodies are rejected uniformly.
        return _plausible_flag(text)
    if _FLAG_BARE_TOKEN_SHAPE.fullmatch(text):
        if _FLAG_PYTHON_EXCEPTION_RE.fullmatch(text):
            return False
        low = text.lower()
        if any(needle in low for needle in _FLAG_BARE_TOKEN_NOISE_NEEDLES):
            return False
        return True
    return False


def build_flag_validation_task(
    candidate: str,
    *,
    source: str,
    priority: int = 99,
) -> Task | None:
    """Build a flag-validate task, or ``None`` if the candidate is clearly junk.

    Workers should treat ``None`` as "skip" — the candidate failed shape checks
    and isn't worth the round-trip through :class:`FlagValidationAgent`.
    Prefer :func:`build_flag_validation_tasks` when you have an iterable of
    candidates; it filters out the ``None`` entries for you.
    """

    if not is_validatable_flag_candidate(candidate):
        return None

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


def build_flag_validation_tasks(
    candidates: Iterable[str],
    *,
    source: str,
    priority: int = 99,
) -> list[Task]:
    """Build flag-validate tasks for every plausible candidate.

    Convenience wrapper around :func:`build_flag_validation_task` that drops
    junk candidates instead of yielding ``None`` entries.  Use this whenever
    the worker has a list of candidates to validate.
    """

    tasks: list[Task] = []
    for candidate in candidates:
        task = build_flag_validation_task(candidate, source=source, priority=priority)
        if task is not None:
            tasks.append(task)
    return tasks


# ---------------------------------------------------------------------------
# Exploit stage
# ---------------------------------------------------------------------------

def build_exploit_hypothesis_task(
    *,
    files_root: str | None = None,
    focus_asset_ids: list[str] | None = None,
    seed_terms: list[str] | None = None,
    priority: int = 76,
) -> Task:
    """Build a deterministic follow-up task for CTF exploit/pivot reasoning."""

    normalized_assets = _merge_unique(focus_asset_ids, limit=8)
    normalized_seed_terms = _merge_unique(seed_terms, limit=12)
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

    normalized_credential_ids = _merge_unique(credential_ids, limit=8)
    normalized_seed_paths = _normalize_paths(seed_paths, limit=16)
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
    normalized_credentials = _merge_unique(credential_ids, limit=8)
    normalized_seed_paths = _normalize_paths(seed_paths, limit=16)
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
