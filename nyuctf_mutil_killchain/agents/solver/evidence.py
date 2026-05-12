"""Solver evidence collection.

Pulls accumulated facts from :class:`GlobalState` and the current task into a
single dataclass that the prompt builder consumes.  No LLM calls and no
filesystem I/O happen here - inputs are read from state only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from nyuctf_mutil_killchain.knowledge import KnowledgeAugmenter, RagContext
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
    binary_disassembly: dict[str, Any] = field(default_factory=dict)
    binary_runs: dict[str, Any] = field(default_factory=dict)
    live_http_observations: list[dict[str, Any]] = field(default_factory=list)
    previous_attempts: list[dict[str, Any]] = field(default_factory=list)
    solver_hints: list[str] = field(default_factory=list)
    related_writeups: list[dict[str, Any]] = field(default_factory=list)
    solver_contract: dict[str, Any] = field(default_factory=dict)

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
        if self.binary_disassembly:
            snapshot["binary_disassembly"] = self.binary_disassembly
        if self.binary_runs:
            snapshot["binary_runs"] = self.binary_runs
        if self.live_http_observations:
            snapshot["live_http_observations"] = self.live_http_observations
        if self.previous_attempts:
            snapshot["previous_solver_attempts"] = self.previous_attempts
        if self.solver_hints:
            snapshot["solver_hints"] = self.solver_hints
        if self.related_writeups:
            snapshot["related_writeups"] = self.related_writeups
        if self.solver_contract:
            snapshot["SOLVER_CONTRACT"] = self.solver_contract
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
        evidence.binary_disassembly = self._collect_binary_disassembly(state)
        evidence.binary_runs = self._collect_binary_runs(state)
        evidence.live_http_observations = self._collect_live_http_observations(state)
        rag_context = (
            self.augmenter.context_for(state) if self.augmenter is not None else None
        )
        evidence.related_writeups = (
            rag_context.prompt_hits(
                max_solution_chars=2400,
                max_description_chars=320,
                max_files=8,
            )
            if rag_context is not None
            else []
        )

        in_chain_attempts = list(task.input_context.get("previous_attempts") or [])
        if in_chain_attempts:
            # Solver-retry path: the in-chain context already carries the
            # last attempts (with structured fingerprint + diagnosis).
            evidence.previous_attempts = in_chain_attempts[-5:]
        else:
            # Planner-proposed path: this is a *fresh* solver chain. Pull the
            # last failed attempts of the same task_type from the cross-task
            # memory so the LLM doesn't repeat the previous chain's broad
            # approach verbatim. Dedup by error_fingerprint so long-tail
            # failure modes (e.g. the same "Could not open output file"
            # stderr across cycles 7 and 11) are preserved even when there
            # are >5 raw failures.
            evidence.previous_attempts = self._memory_to_previous_attempts(
                state, task.task_type
            )
        evidence.solver_contract = self._build_solver_contract(
            task=task,
            evidence=evidence,
            rag_context=rag_context,
        )
        evidence.solver_hints = self._build_solver_hints(evidence)
        return evidence

    @staticmethod
    def _build_solver_contract(
        *,
        task: Task,
        evidence: SolverEvidence,
        rag_context: RagContext | None,
    ) -> dict[str, Any]:
        """Turn task/RAG state into hard requirements for the solver prompt."""

        ctx = task.input_context
        contract: dict[str, Any] = {
            "solver_mode": str(ctx.get("solver_mode") or "standard"),
        }
        failure_class = str(ctx.get("failure_class") or "").strip()
        if failure_class:
            contract["failure_class"] = failure_class
        must_avoid = [str(item) for item in list(ctx.get("must_avoid") or []) if str(item).strip()]
        if must_avoid:
            contract["must_avoid"] = must_avoid[:12]
        required_checks = [
            str(item) for item in list(ctx.get("required_checks") or []) if str(item).strip()
        ]

        if rag_context is not None and (
            rag_context.high_confidence or rag_context.exact_self_hit
        ):
            contract["rag_confidence"] = round(rag_context.top_score, 4)
            contract["rag_top_challenge_id"] = rag_context.top_challenge_id
            contract["rag_exact_self_hit"] = rag_context.exact_self_hit

        if required_checks:
            contract["required_checks"] = required_checks[:16]

        if contract["solver_mode"] == "standard" and not any(
            key in contract for key in ("failure_class", "must_avoid", "required_checks", "rag_confidence")
        ):
            return {}
        return contract

    @staticmethod
    def _memory_to_previous_attempts(
        state: GlobalState, task_type: str
    ) -> list[dict[str, Any]]:
        """Convert recent :class:`TaskAttemptMemory` entries into snapshot dicts.

        Thin wrapper around :meth:`GlobalState.recent_attempts_for` kept for
        backwards-compatibility with the composer's call sites; the real
        dedup/limit logic lives on the state model now so recovery and
        other consumers share it.
        """
        return state.recent_attempts_for(task_type, limit=5)

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
    def _collect_binary_runs(state: GlobalState) -> dict[str, Any]:
        """Surface ``binary_run`` plugin output for the solver prompt.

        Reads every evidence record whose ``tool_name == 'binary_run'`` and
        merges its ``output_context['binary_runs']`` payload keyed by the
        binary filename.  Returns ``{}`` when no run probe has been
        executed.  Recent runs overwrite older entries on conflict so the
        solver sees the freshest observation per binary.
        """
        merged: dict[str, Any] = {}
        for record in state.evidence.values():
            if record.tool_name != "binary_run":
                continue
            payload = (record.extracted or {}).get("output_context", {}) or {}
            runs = payload.get("binary_runs") or {}
            if not isinstance(runs, dict):
                continue
            for binary_name, body in runs.items():
                if isinstance(body, dict) and body.get("invocations"):
                    merged[binary_name] = body
        return merged

    @staticmethod
    def _collect_live_http_observations(state: GlobalState) -> list[dict[str, Any]]:
        """Surface real HTTP responses (headers + set-cookie) for the solver.

        Web exploit writers cannot guess the cookie name or framework from
        a writeup hint — they need to see what the live server *actually*
        sends.  This collector walks ``state.evidence`` for any HTTP tool
        (``http_metadata``, ``http_content``, ``http_path_probe``) and
        extracts ``response_headers`` / ``set_cookie`` / ``http_status``
        into a compact list the solver prompt can read directly.

        Returns at most 6 observations newest-first to bound prompt size.
        """
        http_tools = {"http_metadata", "http_content", "http_path_probe", "http_form_probe"}
        observations: list[dict[str, Any]] = []
        for record in state.evidence.values():
            if record.tool_name not in http_tools:
                continue
            payload = (record.extracted or {}).get("output_context", {}) or {}
            headers = payload.get("response_headers") or {}
            set_cookie = payload.get("set_cookie") or headers.get("set-cookie") or ""
            status = payload.get("http_status")
            url = (
                payload.get("observed_base_url")
                or payload.get("target_url")
                or payload.get("base_url")
                or ""
            )
            if not headers and not set_cookie and status is None:
                continue
            entry: dict[str, Any] = {
                "tool": record.tool_name,
                "url": str(url)[:200],
            }
            if status is not None:
                entry["http_status"] = status
            if set_cookie:
                entry["set_cookie"] = str(set_cookie)[:500]
            if headers:
                # Show the headers most useful for exploit writing.  Drop
                # noise like Date/Etag/X-Trace which bloat prompt with no
                # actionable signal.
                _SKIP = {"date", "etag", "x-trace", "x-runtime", "x-served-by", "via"}
                filtered = {
                    k: str(v)[:300]
                    for k, v in headers.items()
                    if k.lower() not in _SKIP
                }
                if filtered:
                    entry["headers"] = filtered
            observations.append(entry)
        # Most recently observed first, capped.
        observations.reverse()
        return observations[:6]

    @staticmethod
    def _collect_binary_disassembly(state: GlobalState) -> dict[str, Any]:
        """Surface ``binary_disassembly`` evidence for the solver prompt.

        Looks at every evidence record produced by the ``binary_disassembly``
        tool and merges its ``extracted.output_context["disassembly"]``
        payload by binary filename.  Most recent run wins on conflict.
        Returns ``{}`` when no disassembly has been produced this run.
        """
        merged: dict[str, Any] = {}
        # Iterate in insertion order; dict preserves the order evidence was
        # added so newer entries overwrite older per-binary payloads.
        for record in state.evidence.values():
            if record.tool_name != "binary_disassembly":
                continue
            payload = (
                (record.extracted or {}).get("output_context", {})
                or record.result.get("output_context", {})
                or {}
            )
            disasm = payload.get("disassembly") or {}
            if not isinstance(disasm, dict):
                continue
            for binary_name, body in disasm.items():
                if isinstance(body, dict) and (body.get("functions") or body.get("rodata")):
                    merged[binary_name] = body
        return merged

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
