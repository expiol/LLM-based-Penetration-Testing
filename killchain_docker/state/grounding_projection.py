"""State-reference and exploit-grounding projection."""

from __future__ import annotations

from urllib.parse import urlparse
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState


class GroundingProjection:
    """Read-only checks for whether todo context is grounded in current state."""

    def __init__(self, state: "RunState") -> None:
        self.state = state

    def context_refs_existing(self, context: dict[str, object], *keys: str) -> bool:
        return self.refs_existing(
            context, self.state.evidence, *keys
        ) or self.refs_existing(context, self.state.hypotheses, *keys)

    def has_new_fact_refs(
        self,
        context: dict[str, object],
        previous_contexts: list[dict[str, object]],
        *keys: str,
    ) -> bool:
        refs = self.context_values(context, *keys)
        if not refs:
            return False
        if not (
            refs.issubset(self.state.evidence.keys())
            or refs.issubset(self.state.hypotheses.keys())
        ):
            return False
        previous_refs: set[str] = set()
        for previous in previous_contexts:
            previous_refs.update(self.context_values(previous, *keys))
        return not refs.issubset(previous_refs)

    def exploit_grounded(self, context: dict[str, object]) -> bool:
        if self.state.vulnerabilities or self.state.credentials or self.state.sessions:
            return True
        return (
            self.refs_existing(
                context, self.state.findings, "finding_id", "finding_ids"
            )
            or self.refs_existing(
                context,
                self.state.vulnerabilities,
                "vulnerability_id",
                "vulnerability_ids",
            )
            or self.refs_existing(
                context, self.state.credentials, "credential_id", "credential_ids"
            )
            or self.refs_existing(
                context, self.state.sessions, "session_id", "session_ids"
            )
            or self.refs_existing(
                context, self.state.hypotheses, "hypothesis_id", "hypothesis_ids"
            )
            or self.refs_existing(
                context, self.state.evidence, "evidence_id", "evidence_ids"
            )
            or self.refs_observed_endpoint(context)
        )

    @staticmethod
    def refs_existing(
        context: dict[str, object], records: dict[str, object], *keys: str
    ) -> bool:
        refs = GroundingProjection.context_values(context, *keys)
        return bool(refs and refs.issubset(records.keys()))

    def refs_observed_endpoint(self, context: dict[str, object]) -> bool:
        if self.refs_existing(
            context, self.state.endpoints, "endpoint_id", "endpoint_ids"
        ):
            return True
        observed = [
            endpoint
            for endpoint in self.state.endpoints.values()
            if self._endpoint_has_positive_observation(endpoint)
        ]
        if not observed:
            return False
        for endpoint in observed:
            if self._endpoint_url_matches(context, endpoint):
                return True
            if self._endpoint_host_port_matches(context, endpoint):
                return True
        return False

    @staticmethod
    def context_values(context: dict[str, object], *keys: str) -> set[str]:
        refs: set[str] = set()
        for key in keys:
            value = context.get(key)
            if value in (None, "", [], {}, ()):
                continue
            if isinstance(value, bool):
                continue
            if isinstance(value, str):
                text = value.strip()
                if text:
                    refs.add(text)
                continue
            if isinstance(value, (list, tuple, set, frozenset)):
                for item in value:
                    if item is None or isinstance(item, bool):
                        continue
                    text = str(item).strip()
                    if text:
                        refs.add(text)
        return refs

    @staticmethod
    def _endpoint_has_positive_observation(endpoint: object) -> bool:
        if getattr(endpoint, "status_code", None) is not None:
            return True
        if getattr(endpoint, "metadata", None):
            return True
        protocol = str(getattr(endpoint, "protocol", "") or "").lower()
        return bool(
            getattr(endpoint, "hostname", None)
            and getattr(endpoint, "port", None)
            and (protocol not in {"", "http", "https"})
        )

    @staticmethod
    def _endpoint_url_matches(context: dict[str, object], endpoint: object) -> bool:
        for raw in GroundingProjection.context_values(
            context, "url", "base_url", "scope"
        ):
            parsed = GroundingProjection._parse_endpoint_ref(raw)
            if parsed is None:
                continue
            hostname, port = parsed
            if GroundingProjection._same_endpoint(endpoint, hostname, port):
                return True
        return False

    @staticmethod
    def _endpoint_host_port_matches(
        context: dict[str, object], endpoint: object
    ) -> bool:
        hosts = {
            value.lower()
            for value in GroundingProjection.context_values(
                context, "host", "hostname", "server_name"
            )
        }
        ports = GroundingProjection.context_values(context, "port", "ports")
        if not hosts or not ports:
            return False
        endpoint_host = str(getattr(endpoint, "hostname", "") or "").lower()
        endpoint_port = str(getattr(endpoint, "port", "") or "")
        return endpoint_host in hosts and endpoint_port in ports

    @staticmethod
    def _parse_endpoint_ref(raw: object) -> tuple[str, int | None] | None:
        text = str(raw or "").strip()
        if not text:
            return None
        candidate = text if "://" in text else f"//{text}"
        try:
            parsed = urlparse(candidate)
        except ValueError:
            return None
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return None
        try:
            port = parsed.port
        except ValueError:
            port = None
        if port is None and parsed.scheme == "http":
            port = 80
        elif port is None and parsed.scheme == "https":
            port = 443
        return (hostname, port)

    @staticmethod
    def _same_endpoint(endpoint: object, hostname: str, port: int | None) -> bool:
        if str(getattr(endpoint, "hostname", "") or "").lower() != hostname:
            return False
        return port is None or getattr(endpoint, "port", None) == port
