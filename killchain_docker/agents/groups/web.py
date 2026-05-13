"""Web-stage worker group.

Each web task type maps to its own per-task worker class.
"""

from __future__ import annotations

from killchain_docker.agents.enrichment import WebPathProbeAgent
from killchain_docker.agents.web import WebAssessmentAgent
from killchain_docker.agents.web_content import WebContentAgent
from killchain_docker.agents.web_form import WebFormProbeAgent

WEB_WORKERS: tuple[type, ...] = (
    WebAssessmentAgent,
    WebContentAgent,
    WebFormProbeAgent,
    WebPathProbeAgent,
)


__all__ = [
    "WEB_WORKERS",
    "WebAssessmentAgent",
    "WebContentAgent",
    "WebFormProbeAgent",
    "WebPathProbeAgent",
]
