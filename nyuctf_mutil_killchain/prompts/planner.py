"""System prompt for the LLM planner.

The planner sees the full state and proposes a list of next tasks.  No
hard-coded phase machine, no whitelist of approved task types - the LLM
chooses task types from the open vocabulary documented below.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.prompts.types import lookup

TASK_TYPE_VOCABULARY: list[str] = [
    "recon.enumerate_scope",
    "recon.dns_enum",
    "recon.subdomain_discovery",
    "credential.hunt",
    "flag.hunt",
    "artifact.triage",
    "artifact.archive_triage",
    "artifact.binary_triage",
    "artifact.computation_analysis",
    "artifact.deep_review",
    "artifact.runtime_probe",
    "artifact.sqlite_review",
    "artifact.pcap_review",
    "artifact.repo_review",
    "artifact.source_review",
    "host.audit",
    "host.banner_grab",
    "host.port_scan",
    "host.service_fingerprint",
    "web.review_surface",
    "web.content_review",
    "web.form_probe",
    "web.path_probe",
    "web.crawl",
    "web.header_analysis",
    "vuln.scan",
    "vuln.nuclei_probe",
    "vuln.nikto_scan",
    "exploit.hypothesis",
    "exploit.cve_probe",
    "exploit.credential_test",
    "exploit.sqli",
    "post_exploit.loot",
    "post_exploit.lateral_move",
    "flag.validate",
    "solve.generate_script",
]


def build_planner_system_prompt(category: str | None) -> str:
    """Build the LLM planner system prompt for the given challenge category."""
    prompts = lookup(category)
    return (
        f"{prompts.planner_system} {prompts.planner_focus} "
        "You operate within the explicitly approved challenge environment and scope only. "
        "Return only JSON matching the PlannerDecision schema. "
        "You may propose tasks freely from the documented task-type vocabulary. "
        "Use 'solve.generate_script' when you have enough evidence to write an executable solver. "
        "Use 'flag.validate' to confirm any candidate flag against the expected challenge flag. "
        "Set stop_run=true only when you genuinely have nothing further to attempt. "
        "Never propose tasks outside the authorized_scope or the provided challenge files. "
        "Never fabricate vulnerability details, credentials, or flag candidates. "
        "Open vocabulary of task types: " + ", ".join(TASK_TYPE_VOCABULARY)
    )
