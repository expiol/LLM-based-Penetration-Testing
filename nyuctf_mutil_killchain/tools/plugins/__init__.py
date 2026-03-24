"""Per-tool command specifications."""

from . import (
    archive_triage,
    artifact_triage,
    binary_triage,
    host_inventory,
    http_content,
    http_metadata,
    http_path_probe,
    pcap_review,
    repo_review,
    source_review,
    sqlite_review,
    tcp_banner_probe,
    vuln_scan,
)

ALL_COMMAND_TOOLS = (
    http_metadata,
    http_content,
    artifact_triage,
    archive_triage,
    binary_triage,
    sqlite_review,
    pcap_review,
    repo_review,
    source_review,
    host_inventory,
    tcp_banner_probe,
    http_path_probe,
    vuln_scan,
)

__all__ = ["ALL_COMMAND_TOOLS"]
