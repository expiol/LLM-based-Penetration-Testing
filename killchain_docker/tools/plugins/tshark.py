"""tshark — packet capture analysis.

Supports:
  - Display filters and field extraction
  - Rich output parsing: protocol stats, HTTP URLs, DNS queries, credentials
  - Typed state signals: Endpoint for discovered hosts, Credential for cleartext auth
"""

from __future__ import annotations
import re
from collections import Counter
from typing import Any
from killchain_docker.logging_utils import get_logger
from killchain_docker.state.domain import Credential, Endpoint
from killchain_docker.tools.core import (
    ExecutionMode,
    ParsedToolOutput,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolOutput,
    _truncate,
)
from killchain_docker.tools.plugins._base import (
    _flag_candidates_from,
    _require,
    _run,
    _status,
)

LOGGER = get_logger(__name__)
_HTTP_REQ_RE = re.compile(
    "(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\\s+(\\S+)\\s+HTTP/", re.IGNORECASE
)
_HTTP_HOST_RE = re.compile("Host:\\s*(\\S+)", re.IGNORECASE)
_DNS_QUERY_RE = re.compile("Standard query.*?(?:A|AAAA|CNAME)\\s+(\\S+)", re.IGNORECASE)
_AUTH_BASIC_RE = re.compile("Authorization:\\s*Basic\\s+(\\S+)", re.IGNORECASE)
_FTP_USER_RE = re.compile("USER\\s+(\\S+)", re.IGNORECASE)
_FTP_PASS_RE = re.compile("PASS\\s+(\\S+)", re.IGNORECASE)
_IP_RE = re.compile("\\b(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\\b")
_PROTO_RE = re.compile(
    "\\b(TCP|UDP|HTTP|DNS|FTP|SSH|TLS|SMTP|ICMP|ARP)\\b", re.IGNORECASE
)


class TsharkPlugin:
    name = "tshark"
    mode = ExecutionMode.LOCAL_COMMAND

    def __init__(self, *, argv_prefix: list[str] | None = None) -> None:
        self.argv_prefix = list(argv_prefix or [])

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        path = _require(request.metadata, "path", self.name)
        filt = str(request.metadata.get("filter") or "")
        fields = str(request.metadata.get("fields") or "")
        extra = str(request.metadata.get("extra_args") or "")
        cmd = f"tshark -r {path}"
        if filt:
            cmd += f" -Y '{filt}'"
        if fields:
            cmd += f" -T fields {' '.join((f'-e {f}' for f in fields.split(',')))}"
        if extra:
            cmd += f" {extra}"
        return _run(
            self.name, [*self.argv_prefix, "bash", "-c", cmd], request.timeout_s
        )


def build_output(
    request: ToolExecutionRequest,
    result: ToolExecutionResult,
    _parsed: ParsedToolOutput,
) -> ToolOutput:
    path = str(request.metadata.get("path") or "")
    filt = str(request.metadata.get("filter") or "")
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    status = _status(result)
    packets = [line for line in stdout.splitlines() if line.strip()]
    proto_counts: Counter[str] = Counter()
    for line in packets:
        for m in _PROTO_RE.finditer(line):
            proto_counts[m.group(1).upper()] += 1
    ip_set: set[str] = set()
    for line in packets:
        for m in _IP_RE.finditer(line):
            ip = m.group(1)
            if not ip.startswith("0.") and (not ip.startswith("255.")):
                ip_set.add(ip)
    http_requests: list[dict[str, str]] = []
    current_host = ""
    for line in packets:
        hm = _HTTP_HOST_RE.search(line)
        if hm:
            current_host = hm.group(1)
        rm = _HTTP_REQ_RE.search(line)
        if rm:
            http_requests.append(
                {
                    "method": rm.group(1).upper(),
                    "path": rm.group(2),
                    "host": current_host,
                }
            )
    dns_queries: list[str] = list(
        dict.fromkeys((m.group(1) for m in _DNS_QUERY_RE.finditer(stdout)))
    )
    credentials: list[Credential] = []
    for m in _AUTH_BASIC_RE.finditer(stdout):
        import base64

        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            if ":" in decoded:
                user, passwd = decoded.split(":", 1)
                credentials.append(
                    Credential(
                        credential_id=f"tshark-basic-{user[:32]}",
                        username=user,
                        secret_ref=f"pcap-basic:{passwd}",
                        credential_type="http_basic",
                        source="tshark",
                        metadata={"pcap": path},
                    )
                )
        except Exception:
            LOGGER.debug(
                "failed to decode HTTP basic credential from tshark output",
                exc_info=True,
                extra={"pcap": path},
            )
    ftp_users = _FTP_USER_RE.findall(stdout)
    ftp_passes = _FTP_PASS_RE.findall(stdout)
    for user in dict.fromkeys(ftp_users):
        passwd = ftp_passes[0] if ftp_passes else ""
        credentials.append(
            Credential(
                credential_id=f"tshark-ftp-{user[:32]}",
                username=user,
                secret_ref=f"pcap-ftp:{passwd}" if passwd else "pcap-ftp:unknown",
                credential_type="ftp",
                source="tshark",
                metadata={"pcap": path},
            )
        )
    endpoints: list[Endpoint] = []
    for ip in sorted(ip_set)[:20]:
        endpoints.append(
            Endpoint(hostname=ip, metadata={"source": "pcap", "pcap_file": path})
        )
    flags = _flag_candidates_from(stdout, source="tshark")
    summary = f"tshark {path}: {len(packets)} packet(s)"
    if proto_counts:
        top_protos = [
            f"{count} {proto}" for proto, count in proto_counts.most_common(4)
        ]
        summary += f" ({', '.join(top_protos)})"
    if filt:
        summary += f" [filter: {filt[:40]}]"
    if http_requests:
        summary += f", {len(http_requests)} HTTP request(s)"
    if credentials:
        summary += f", {len(credentials)} credential(s)"
    if flags:
        summary += f" — {len(flags)} flag candidate(s)"
    output_context: dict[str, Any] = {
        "path": path,
        "filter": filt,
        "packet_count": len(packets),
    }
    if status.value == "success" and (not packets):
        output_context["failure_kind"] = "empty_result"
        output_context["failure_detail"] = (
            "tshark completed but produced no packets"
            + (f" for filter {filt!r}" if filt else "")
        )
        output_context["result_quality"] = "empty_result"
    if proto_counts:
        output_context["protocol_counts"] = dict(proto_counts.most_common(10))
    if ip_set:
        output_context["observed_ips"] = sorted(ip_set)[:30]
    if http_requests:
        output_context["http_requests"] = http_requests[:20]
    if dns_queries:
        output_context["dns_queries"] = dns_queries[:20]
    return ToolOutput(
        status=status,
        summary=summary,
        output_text=_truncate(stdout, 4000),
        raw_log=_truncate(stdout + stderr, 6000),
        output_context=output_context,
        flag_candidates=flags,
        credentials=credentials,
        endpoints=endpoints,
    )
