"""Solver evidence collection.

Pulls accumulated facts from :class:`GlobalState` and the current task into a
single dataclass that the prompt builder consumes.  No LLM calls and no
filesystem I/O happen here - inputs are read from state only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nyuctf_mutil_killchain.knowledge import KnowledgeAugmenter
from nyuctf_mutil_killchain.state import FileKind, GlobalState, Task, classify


_DEFAULT_FILES_ROOT = "/home/ctfplayer/ctf_files"
_MAX_SOURCE_CHARS_PER_FILE = 12000
_MAX_TOTAL_SOURCE_CHARS = 36000


@dataclass
class SolverEvidence:
    """Compact view of what the solver LLM sees about the challenge."""

    challenge: dict[str, Any]
    files_root: str
    timeout_s: int
    attempt_number: int
    challenge_source_files: list[dict[str, str]] = field(default_factory=list)
    archive_contents: dict[str, list[str]] = field(default_factory=dict)
    source_evidence: list[dict[str, str]] = field(default_factory=list)
    tcp_banners: dict[str, str] = field(default_factory=dict)
    assets: list[dict[str, Any]] = field(default_factory=list)
    credentials: list[dict[str, Any]] = field(default_factory=list)
    key_findings: list[dict[str, Any]] = field(default_factory=list)
    file_contents: list[dict[str, str]] = field(default_factory=list)
    previous_attempts: list[dict[str, Any]] = field(default_factory=list)
    solver_hints: list[str] = field(default_factory=list)
    related_writeups: list[dict[str, Any]] = field(default_factory=list)

    @property
    def category(self) -> str:
        return str(self.challenge.get("category") or "misc").lower()

    @property
    def flag_format(self) -> str | None:
        return self.challenge.get("flag_format")

    def to_snapshot(self) -> dict[str, Any]:
        """Serialize to the dict shape expected in the user prompt."""
        snapshot: dict[str, Any] = {
            "objective": self.challenge.get("objective_text", ""),
            "challenge": {
                "name": self.challenge.get("name"),
                "category": self.challenge.get("category"),
                "flag_format": self.challenge.get("flag_format"),
                "description": self.challenge.get("description", "")[:500],
                "files": self.challenge.get("files", []),
                "server_name": self.challenge.get("server_name"),
                "port": self.challenge.get("port"),
            },
            "files_root": self.files_root,
        }
        if self.challenge_source_files:
            snapshot["challenge_source_files"] = self.challenge_source_files
        if self.archive_contents:
            snapshot["archive_contents"] = self.archive_contents
        if self.source_evidence:
            snapshot["source_evidence"] = self.source_evidence
        if self.tcp_banners:
            snapshot["tcp_banners"] = self.tcp_banners
        if self.assets:
            snapshot["assets"] = self.assets
        if self.credentials:
            snapshot["credentials"] = self.credentials
        if self.key_findings:
            snapshot["key_findings"] = self.key_findings
        if self.file_contents:
            snapshot["file_contents"] = self.file_contents
        if self.previous_attempts:
            snapshot["previous_solver_attempts"] = self.previous_attempts
        if self.solver_hints:
            snapshot["solver_hints"] = self.solver_hints
        if self.related_writeups:
            snapshot["related_writeups"] = self.related_writeups
        return snapshot


class SolverEvidenceComposer:
    """Build a :class:`SolverEvidence` snapshot from current state.

    Optionally accepts a :class:`KnowledgeAugmenter` so the solver prompt
    receives the same RAG hits the planner sees.  Without an augmenter
    the composer still works — it just emits an empty
    ``related_writeups`` list — so existing tests that construct
    ``SolverEvidenceComposer()`` directly continue to function.
    """

    def __init__(self, augmenter: KnowledgeAugmenter | None = None) -> None:
        self.augmenter = augmenter

    def compose(self, task: Task, state: GlobalState) -> SolverEvidence:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        files_root = str(task.input_context.get("files_root") or _DEFAULT_FILES_ROOT)
        attempt = int(task.input_context.get("attempt_number", 1))
        timeout = int(task.input_context.get("solver_timeout_s", 60))

        challenge = {
            **challenge_meta,
            "objective_text": state.objective,
            "description": state.objective,
        }

        evidence = SolverEvidence(
            challenge=challenge,
            files_root=files_root,
            timeout_s=timeout,
            attempt_number=attempt,
        )

        evidence.challenge_source_files = self._collect_source_files(state, files_root)
        evidence.archive_contents = self._collect_archive_contents(state)
        evidence.source_evidence = self._collect_source_evidence(state)
        evidence.tcp_banners = self._collect_tcp_banners(state)
        evidence.assets = self._collect_assets(state)
        evidence.credentials = self._collect_credentials(state)
        evidence.key_findings = self._collect_key_findings(state)
        evidence.file_contents = self._collect_file_contents(state)
        evidence.related_writeups = (
            self.augmenter.for_solver(state) if self.augmenter is not None else []
        )

        in_chain_attempts = list(task.input_context.get("previous_attempts") or [])
        if in_chain_attempts:
            # Solver-retry path: the in-chain context already carries the
            # last attempts (with structured fingerprint + diagnosis).
            evidence.previous_attempts = in_chain_attempts[-3:]
        else:
            # Planner-proposed path: this is a *fresh* solver chain.  Pull
            # the last failed attempts of the same task_type from the
            # cross-task memory so the LLM doesn't repeat the previous
            # chain's broad approach verbatim (the historypeats failure
            # mode: 22 unique solver titles, none of which inherited the
            # previous chain's stdout/stderr).
            evidence.previous_attempts = self._memory_to_previous_attempts(
                state, task.task_type
            )
        evidence.solver_hints = self._build_solver_hints(evidence)
        return evidence

    @staticmethod
    def _memory_to_previous_attempts(
        state: GlobalState, task_type: str
    ) -> list[dict[str, Any]]:
        """Convert the last K :class:`TaskAttemptMemory` entries into snapshot dicts.

        Returns at most 3 entries (newest last) shaped like the in-chain
        ``previous_attempts`` list so the prompt builder doesn't have to
        special-case the source.
        """
        memory = state.task_type_memory.get(task_type) or []
        attempts: list[dict[str, Any]] = []
        # Only surface the most recent 3 to keep the prompt tight.
        for entry in memory[-3:]:
            attempts.append(
                {
                    "attempt": 0,  # cross-chain: no in-chain attempt number
                    "task_id": entry.task_id,
                    "title": entry.title,
                    "summary": entry.summary,
                    "error": entry.error,
                    "stdout": entry.stdout_preview,
                    "stderr": entry.stderr_preview,
                    "solver_code_preview": entry.solver_code_preview,
                    "error_fingerprint": entry.error_fingerprint,
                    "source": "cross_chain_memory",
                }
            )
        return attempts

    # -----------------------------------------------------------------
    # Internal collectors
    # -----------------------------------------------------------------

    @staticmethod
    def _collect_source_files(state: GlobalState, files_root: str) -> list[dict[str, str]]:
        challenge_meta = state.metadata.get("challenge", {}) or {}
        filenames = list(challenge_meta.get("files", []) or [])
        if not filenames:
            return []

        collected: list[dict[str, str]] = []
        total_chars = 0

        for name in filenames:
            if classify(name) != FileKind.SOURCE:
                collected.append({
                    "filename": name,
                    "note": f"binary file (skipped content, available at {files_root}/{name})",
                })
                continue

            snippet = SolverEvidenceComposer._find_source_snippet(state, name)
            if snippet:
                budget = min(
                    _MAX_SOURCE_CHARS_PER_FILE,
                    _MAX_TOTAL_SOURCE_CHARS - total_chars,
                )
                if budget > 200:
                    excerpt = snippet[:budget]
                    collected.append({"filename": name, "content": excerpt})
                    total_chars += len(excerpt)
                    continue

            collected.append({
                "filename": name,
                "note": f"source file at {files_root}/{name} (read it in your script with open())",
            })
            if total_chars >= _MAX_TOTAL_SOURCE_CHARS:
                break

        if total_chars < _MAX_TOTAL_SOURCE_CHARS:
            extracted_members: list[str] = []
            for finding in state.findings.values():
                am = finding.metadata.get("archive_members")
                if isinstance(am, dict):
                    for members in am.values():
                        extracted_members.extend(members)

            already = {item["filename"] for item in collected}
            for member in extracted_members:
                if member in already or classify(member) != FileKind.SOURCE:
                    continue
                snippet = SolverEvidenceComposer._find_source_snippet(state, member)
                if snippet:
                    budget = min(
                        _MAX_SOURCE_CHARS_PER_FILE,
                        _MAX_TOTAL_SOURCE_CHARS - total_chars,
                    )
                    if budget > 200:
                        excerpt = snippet[:budget]
                        collected.append({"filename": member, "content": excerpt})
                        total_chars += len(excerpt)
                else:
                    collected.append({
                        "filename": member,
                        "note": f"extracted archive member at {files_root}/{member} (read it with open())",
                    })
                if total_chars >= _MAX_TOTAL_SOURCE_CHARS:
                    break

        return collected

    @staticmethod
    def _find_source_snippet(state: GlobalState, filename: str) -> str:
        for finding in state.findings.values():
            snippet = finding.metadata.get("source_snippet") or ""
            if not snippet or len(snippet) <= 100:
                continue
            description = finding.description or ""
            if filename in description:
                return snippet
            if filename in (finding.evidence_refs or []):
                return snippet

        for ev in state.evidence.values():
            result = ev.result or {}
            preview = result.get("stdout_preview") or ev.extracted.get("stdout_preview") or ""
            if filename in preview and len(preview) > 200:
                return preview
        return ""

    @staticmethod
    def _collect_archive_contents(state: GlobalState) -> dict[str, list[str]]:
        contents: dict[str, list[str]] = {}
        for finding in state.findings.values():
            members = finding.metadata.get("archive_members")
            if isinstance(members, dict):
                contents.update(members)
        return contents

    @staticmethod
    def _collect_source_evidence(state: GlobalState) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for finding in state.findings.values():
            meta = finding.metadata or {}
            if meta.get("source") in {"source_review", "computation_analysis", "runtime_probe"}:
                for key in ("stdout_preview", "source_snippet", "function_inventory", "interesting_routes"):
                    if meta.get(key):
                        results.append({"source": str(finding.title), key: str(meta[key])[:1500]})
            if meta.get("runtime_outputs"):
                for output in meta["runtime_outputs"][:3]:
                    results.append({"runtime_output": output})
            if meta.get("recovered_plaintexts"):
                results.append({"recovered_plaintexts": meta["recovered_plaintexts"][:3]})
        return results[:16]

    @staticmethod
    def _collect_tcp_banners(state: GlobalState) -> dict[str, str]:
        banners: dict[str, str] = {}
        for finding in state.findings.values():
            meta = finding.metadata or {}
            if meta.get("source") == "tcp_banner_probe":
                for port_str, banner_text in (meta.get("banner_hits") or {}).items():
                    banners[port_str] = str(banner_text)[:300]
        return banners

    @staticmethod
    def _collect_assets(state: GlobalState) -> list[dict[str, Any]]:
        return [
            {
                "asset_id": asset.asset_id,
                "hostname": asset.hostname,
                "base_url": asset.base_url,
                "services": [
                    {"port": s.port, "name": s.name, "product": s.product}
                    for s in asset.services
                ],
            }
            for asset in state.assets.values()
        ]

    @staticmethod
    def _collect_credentials(state: GlobalState) -> list[dict[str, Any]]:
        return [
            {
                "credential_id": cred.credential_id,
                "username": cred.username,
                "credential_type": cred.credential_type,
                "secret_value": cred.metadata.get("secret_value", ""),
            }
            for cred in list(state.credentials.values())[:8]
        ]

    @staticmethod
    def _collect_key_findings(state: GlobalState) -> list[dict[str, Any]]:
        return [
            {
                "title": f.title,
                "severity": f.severity,
                "description": (f.description or "")[:500],
                "evidence_refs": f.evidence_refs[:5],
            }
            for f in list(state.findings.values())[-20:]
        ]

    @staticmethod
    def _collect_file_contents(state: GlobalState) -> list[dict[str, str]]:
        results: list[dict[str, str]] = []
        for task_entry in state.task_chain.tasks[-16:]:
            ctx = task_entry.output_context or {}
            for key in ("source_snippets", "file_previews", "interesting_strings", "blob_candidates"):
                if ctx.get(key):
                    results.append({key: str(ctx[key])[:1500]})
        return results[:12]

    @staticmethod
    def _build_solver_hints(evidence: SolverEvidence) -> list[str]:
        hints: list[str] = []
        if evidence.archive_contents:
            flat_members = [
                member
                for members_list in evidence.archive_contents.values()
                for member in members_list
            ]
            if flat_members:
                hints.append(
                    f"Archives have been extracted to {evidence.files_root}. "
                    f"Inner files: {', '.join(flat_members[:20])}. "
                    f"Read them directly with open() from that directory."
                )
        if evidence.tcp_banners:
            non_http_ports = [
                p for p, b in evidence.tcp_banners.items()
                if not b.upper().startswith(("HTTP/", "<!DOCTYPE", "<HTML"))
            ]
            if non_http_ports:
                hints.append(
                    f"Ports {', '.join(non_http_ports)} appear to run non-HTTP services. "
                    f"Use pwntools (from pwn import remote) or raw sockets for interaction. "
                    f"Set timeouts and handle multi-round interactive protocols."
                )
        return hints
