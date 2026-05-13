"""Web-stage worker group.

Each web task type maps to its own per-task worker class.
"""

from __future__ import annotations

from nyuctf_mutil_killchain.agents.enrichment import WebPathProbeAgent
from nyuctf_mutil_killchain.agents.web import WebAssessmentAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.agents.web_form import WebFormProbeAgent

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
