"""Task dedupe-key derivation and merging.

Computes a stable :attr:`Task.dedupe_key` for each :class:`PlannedTask` so
that follow-up cycles converge on the same task identity, and drops any
proposal whose dedupe_key already lives in the task chain.

This is the only "filtering" allowed in the planner pipeline - it strips
duplicates only.  It never suppresses unique tasks.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.orchestrator.planning.schemas import PlannedTask
from nyuctf_mutil_killchain.state import GlobalState


class TaskDeduper:
    """Assign stable dedupe_keys and merge proposals against the task chain.

    The deduper always overwrites the LLM-supplied ``dedupe_key`` with the
    deterministic :meth:`default_key` derived from ``task_type + input_context``.
    Two tasks with identical input_context will always collide on dedupe_key,
    regardless of cosmetic differences in the LLM's proposed key.  If the LLM
    wants to schedule a task variant, it must change the input_context (the
    real differentiator), not just the dedupe_key string.
    """

    def merge(
        self,
        proposed: list[PlannedTask],
        state: GlobalState,
        existing_keys: set[str] | None = None,
    ) -> list[PlannedTask]:
        seen = set(existing_keys or set())
        merged: list[PlannedTask] = []
        for task in proposed:
            task.dedupe_key = self.default_key(task)
            if task.dedupe_key in seen:
                continue
            seen.add(task.dedupe_key)
            merged.append(task)
        return merged

    @staticmethod
    def default_key(task: PlannedTask) -> str:
        """Return a stable dedupe key for *task* if none is set."""
        ctx = task.input_context or {}

        if task.task_type == "recon.enumerate_scope":
            return f"bootstrap:recon:{ctx.get('scope', task.title)}"
        if task.task_type == "web.review_surface":
            return f"web-review:{ctx.get('asset_id', task.title)}:{ctx.get('base_url', task.title)}"
        if task.task_type == "web.content_review":
            return f"web-content:{ctx.get('asset_id', task.title)}:{ctx.get('base_url', task.title)}"
        if task.task_type == "artifact.triage":
            return "artifact-triage:challenge-files"
        if task.task_type == "credential.hunt":
            return "credential-hunt:" + str(ctx.get("files_root", "/home/ctfplayer/ctf_files"))
        if task.task_type == "flag.hunt":
            return "flag-hunt:" + str(ctx.get("files_root", "/home/ctfplayer/ctf_files"))
        if task.task_type == "artifact.binary_triage":
            files = ctx.get("binary_files", [])
            return "artifact-binary-triage:" + ",".join(files[:8])
        if task.task_type == "artifact.computation_analysis":
            files = ctx.get("source_files", [])
            return "artifact-computation-analysis:" + ",".join(files[:8])
        if task.task_type == "artifact.deep_review":
            kind = ctx.get("analysis_kind", task.title)
            for field in ("archive_files", "binary_files", "database_files", "pcap_files", "repo_paths"):
                files = ctx.get(field, [])
                if files:
                    return f"artifact-deep-review:{kind}:{','.join(files[:8])}"
            return f"artifact-deep-review:{kind}"
        if task.task_type == "artifact.runtime_probe":
            return "artifact-runtime-probe:" + ",".join(ctx.get("source_files", [])[:8])
        if task.task_type == "artifact.archive_triage":
            return "artifact-archive-triage:" + ",".join(ctx.get("archive_files", [])[:8])
        if task.task_type == "artifact.sqlite_review":
            return "artifact-sqlite-review:" + ",".join(ctx.get("database_files", [])[:8])
        if task.task_type == "artifact.pcap_review":
            return "artifact-pcap-review:" + ",".join(ctx.get("pcap_files", [])[:8])
        if task.task_type == "artifact.repo_review":
            return "artifact-repo-review:" + ",".join(ctx.get("repo_paths", [])[:8])
        if task.task_type == "artifact.source_review":
            return "artifact-source-review:" + ",".join(ctx.get("source_files", [])[:8])
        if task.task_type in {"host.audit", "host.port_scan"}:
            return f"host-audit:{ctx.get('asset_id', task.title)}"
        if task.task_type == "host.banner_grab":
            ports = ctx.get("ports", [])
            return f"host-banner:{ctx.get('asset_id', task.title)}:{','.join(str(p) for p in ports[:8])}"
        if task.task_type in {"vuln.scan", "vuln.nuclei_probe"}:
            return f"vuln-scan:{ctx.get('asset_id', task.title)}"
        if task.task_type == "exploit.credential_test":
            credential_ids = ctx.get("credential_ids", [])
            return (
                f"exploit-credential-test:{ctx.get('asset_id', task.title)}:"
                f"{','.join(str(item) for item in credential_ids[:6])}"
            )
        if task.task_type == "exploit.hypothesis":
            focus_ids = ctx.get("focus_asset_ids", [])
            seed_terms = ctx.get("seed_terms", [])
            return "exploit-hypothesis:" + ",".join(
                [
                    *(str(item) for item in focus_ids[:4]),
                    *(str(item) for item in seed_terms[:4]),
                ]
            )
        if task.task_type == "exploit.cve_probe":
            ports = ctx.get("ports", [])
            credential_ids = ctx.get("credential_ids", [])
            target = ctx.get("base_url") or ctx.get("hostname") or task.title
            return (
                f"exploit-cve-probe:{ctx.get('asset_id', task.title)}:{target}:"
                f"{','.join(str(p) for p in ports[:6])}:"
                f"{','.join(str(item) for item in credential_ids[:4])}"
            )
        if task.task_type == "exploit.sqli":
            target = ctx.get("base_url") or ctx.get("hostname") or task.title
            return f"exploit-sqli:{ctx.get('asset_id', task.title)}:{target}"
        if task.task_type == "web.path_probe":
            paths = ctx.get("paths", [])
            return (
                f"web-path-probe:{ctx.get('asset_id', task.title)}:"
                f"{ctx.get('base_url', task.title)}:{','.join(paths[:8])}"
            )
        if task.task_type == "web.crawl":
            return f"web-crawl:{ctx.get('asset_id', task.title)}:{ctx.get('base_url', task.title)}"
        if task.task_type == "web.header_analysis":
            return f"web-header-analysis:{ctx.get('asset_id', task.title)}:{ctx.get('base_url', task.title)}"
        if task.task_type == "web.form_probe":
            return f"web-form-probe:{ctx.get('asset_id', task.title)}:{ctx.get('page_url', task.title)}"
        if task.task_type in {"host.port_scan", "host.service_fingerprint"}:
            return f"{task.task_type}:{ctx.get('asset_id', task.title)}:{ctx.get('hostname', '')}"
        if task.task_type in {"post_exploit.loot", "post_exploit.lateral_move"}:
            return f"{task.task_type}:{ctx.get('asset_id', task.title)}"
        if task.task_type == "flag.validate":
            return f"flag-validate:{ctx.get('candidate_flag', task.title)}"
        return f"{task.task_type}:{task.title}"
