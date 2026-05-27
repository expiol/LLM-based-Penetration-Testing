"""NVD CVE search adapter.

Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
Anonymous access has a 5-request-per-30-second rate limit, so we additionally
honour our own per-source budget enforced at the augmenter level.
"""

from __future__ import annotations

from typing import Any, Callable
from urllib.parse import urlencode

from killchain_docker.intelligence.hit import KnowledgeHit


SOURCE_NAME = "nvd"
_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search(
    *,
    query: str,
    category: str,
    keywords: tuple[str, ...],
    fetch_json: Callable[..., dict[str, Any]],
    limit: int = 3,
) -> list[KnowledgeHit]:
    text = (query or " ".join(keywords)).strip()
    if not text:
        return []
    params = {
        "keywordSearch": text[:256],
        "resultsPerPage": str(max(1, min(limit * 2, 10))),
    }
    url = f"{_BASE_URL}?{urlencode(params)}"
    payload = fetch_json(url)
    hits: list[KnowledgeHit] = []
    vulnerabilities = payload.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return []
    for entry in vulnerabilities[:limit]:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue
        descriptions = cve.get("descriptions") or []
        text_value = ""
        if isinstance(descriptions, list):
            for description in descriptions:
                if (
                    isinstance(description, dict)
                    and str(description.get("lang", "")).lower() == "en"
                ):
                    text_value = str(description.get("value") or "")[:1500]
                    break
        metrics = cve.get("metrics") or {}
        score = _cvss(metrics)
        hits.append(
            KnowledgeHit(
                source=f"web/{SOURCE_NAME}",
                scope="",
                key=cve_id,
                title=cve_id,
                summary=text_value[:280] or cve_id,
                value=text_value or cve_id,
                score=score,
                extra={"category": category},
            )
        )
    return hits


def _cvss(metrics: dict[str, Any]) -> float:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key)
        if not isinstance(items, list) or not items:
            continue
        first = items[0] if isinstance(items[0], dict) else None
        if not first:
            continue
        data = first.get("cvssData") or {}
        try:
            return float(data.get("baseScore") or 0.0)
        except (TypeError, ValueError):
            return 0.0
    return 0.0
