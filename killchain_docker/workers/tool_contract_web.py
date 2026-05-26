"""Metadata contracts for network and web capabilities."""

from __future__ import annotations

from killchain_docker.tools.capabilities import ToolCapability

WEB_TOOL_METADATA_CONTRACTS: dict[ToolCapability, dict[str, object]] = {
    ToolCapability.NMAP: {
        "required": ["target"],
        "optional": ["ports", "scan_type", "extra_args"],
        "notes": "Port scanning. scan_type default '-sV'. ports e.g. '1-1000' or '80,443,8080'.",
    },
    ToolCapability.CURL: {
        "required": ["url"],
        "optional": [
            "method",
            "headers",
            "data",
            "extra_args",
            "session_id",
            "cookies",
            "follow_redirects",
            "auth",
        ],
        "notes": (
            "HTTP/HTTPS request only. method default 'GET'. headers is a dict. data is string body. "
            "session_id enables cookie jar persistence across requests (same id = same cookies). "
            "cookies is a string 'k1=v1; k2=v2' for one-shot cookies. "
            "follow_redirects=true adds -L. auth is 'user:pass' for HTTP basic auth. "
            "For tcp:// or custom binary/text protocols, use script.exec with sockets."
        ),
    },
    ToolCapability.SQLMAP: {
        "required": ["url"],
        "optional": [
            "extra_args",
            "cookie",
            "session_id",
            "headers",
            "data",
            "method",
        ],
        "notes": (
            "SQL injection scan. Runs --batch --level=3 --risk=2 by default. "
            "cookie is 'k=v; k2=v2' for authenticated testing. "
            "session_id reuses cookie jar from a prior curl session. "
            "headers is a dict. data is POST body string. method forces HTTP verb."
        ),
    },
    ToolCapability.NIKTO: {
        "required": ["target"],
        "optional": ["extra_args", "cookie", "session_id", "tuning"],
        "notes": (
            "Web vulnerability scan. target is a URL or host:port. "
            "cookie is 'k=v; k2=v2' for authenticated scanning. "
            "session_id reuses cookie jar from a prior curl session. "
            "tuning selects scan categories (e.g. '1' info disclosure, '2' misconfiguration)."
        ),
    },
}
