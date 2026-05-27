"""Policy gates for opt-in cybersecurity web retrieval."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Hard cap: limit one run's outbound calls so that a stuck loop cannot exhaust
# external rate limits or balloon costs.
MAX_CALLS_PER_RUN = 30
PER_SOURCE_CALLS = 10
HTTP_TIMEOUT_S = 10.0
MAX_BODY_BYTES = 8 * 1024
MAX_RESULTS_PER_QUERY = 5

# Allowlisted hosts — only public security data feeds.
ALLOWED_HOSTS = (
    "services.nvd.nist.gov",
    "attack.mitre.org",
    "raw.githubusercontent.com",  # MITRE ATT&CK STIX bundle, Exploit-DB CSV mirror
    "www.exploit-db.com",
    "gitlab.com",  # Exploit-DB official mirror
)


_FLAG_CONTEXT_RE = re.compile(
    r"\b[A-Za-z0-9_]{2,32}\{[^{}\n]{1,160}\}"  # flag literal
)
_CHALLENGE_NAME_RE = re.compile(r"\b[Cc]hallenge[-_ ][A-Za-z0-9_-]+\b")


@dataclass(frozen=True)
class WebQueryRedaction:
    """Result of stripping benchmark identifiers from a query string."""

    query: str
    redactions: tuple[str, ...]


def redact_query(text: str, *, blocked_tokens: tuple[str, ...] = ()) -> WebQueryRedaction:
    """Strip benchmark-leaking tokens before sending text to a web source.

    The killchain framework forbids any benchmark-aware behaviour; web
    retrieval must therefore never echo a challenge id, year, event, expected
    flag, or canonical name to an external service.
    """

    redactions: list[str] = []
    cleaned = _FLAG_CONTEXT_RE.sub(" ", text)
    if cleaned != text:
        redactions.append("flag_literal")
    cleaned, count = _CHALLENGE_NAME_RE.subn(" ", cleaned)
    if count:
        redactions.append("challenge_name")
    for token in blocked_tokens:
        token = (token or "").strip()
        if not token:
            continue
        if token.lower() in cleaned.lower():
            cleaned = re.sub(re.escape(token), " ", cleaned, flags=re.IGNORECASE)
            redactions.append(f"blocked:{token[:24]}")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return WebQueryRedaction(query=cleaned, redactions=tuple(redactions))


def host_allowed(host: str) -> bool:
    """Return True when ``host`` is on the cybersecurity-data allowlist."""

    return any(host == allowed or host.endswith("." + allowed) for allowed in ALLOWED_HOSTS)
