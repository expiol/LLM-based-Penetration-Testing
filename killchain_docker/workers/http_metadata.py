"""HTTP tool metadata normalization."""

from __future__ import annotations

from killchain_docker.tools.core import ToolExecutionError, _first_string
from killchain_docker.tools.plugins.curl import unsupported_url_scheme_reason
from killchain_docker.workers.metadata_common import populated_contract_fields


def normalize_curl_metadata(
    raw: dict[str, object], contract: dict[str, object]
) -> dict[str, object]:
    url = _first_string(raw["url"])
    scheme_reason = unsupported_url_scheme_reason(url)
    if scheme_reason:
        raise ToolExecutionError(f"curl blocked: {scheme_reason}")
    return populated_contract_fields(raw, contract)
