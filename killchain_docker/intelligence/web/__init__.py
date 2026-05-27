"""Web subsystem public surface."""

from killchain_docker.intelligence.web.cache import CACHE_TTL_S, WebCache
from killchain_docker.intelligence.web.client import WebFetchError, fetch_json
from killchain_docker.intelligence.web.policy import (
    ALLOWED_HOSTS,
    HTTP_TIMEOUT_S,
    MAX_BODY_BYTES,
    MAX_CALLS_PER_RUN,
    MAX_RESULTS_PER_QUERY,
    PER_SOURCE_CALLS,
    WebQueryRedaction,
    host_allowed,
    redact_query,
)
from killchain_docker.intelligence.web.retriever import WebBudget, WebRetriever

__all__ = [
    "ALLOWED_HOSTS",
    "CACHE_TTL_S",
    "HTTP_TIMEOUT_S",
    "MAX_BODY_BYTES",
    "MAX_CALLS_PER_RUN",
    "MAX_RESULTS_PER_QUERY",
    "PER_SOURCE_CALLS",
    "WebBudget",
    "WebCache",
    "WebFetchError",
    "WebQueryRedaction",
    "WebRetriever",
    "fetch_json",
    "host_allowed",
    "redact_query",
]
