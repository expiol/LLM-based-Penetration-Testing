"""MITRE ATT&CK Enterprise technique lookup.

Pulls the Enterprise STIX bundle from the public mitre/cti GitHub mirror
and indexes it on first use. The bundle is large; we fetch it once via the
caching layer and then filter locally.
"""

from __future__ import annotations

from typing import Any, Callable

from killchain_docker.intelligence.hit import KnowledgeHit


SOURCE_NAME = "mitre"
_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def search(
    *,
    query: str,
    category: str,
    keywords: tuple[str, ...],
    fetch_json: Callable[..., dict[str, Any]],
    limit: int = 3,
) -> list[KnowledgeHit]:
    bundle = fetch_json(_STIX_URL, max_bytes=8 * 1024 * 1024)
    objects = bundle.get("objects") or []
    if not isinstance(objects, list):
        return []
    text_tokens = _tokens(query, keywords)
    if not text_tokens:
        return []
    scored: list[tuple[float, KnowledgeHit]] = []
    for entry in objects:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "attack-pattern":
            continue
        if entry.get("revoked") or entry.get("x_mitre_deprecated"):
            continue
        name = str(entry.get("name") or "").strip()
        description = str(entry.get("description") or "")[:1500]
        external = entry.get("external_references") or []
        attack_id = ""
        if isinstance(external, list):
            for ref in external:
                if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack":
                    attack_id = str(ref.get("external_id") or "").strip()
                    break
        if not attack_id or not name:
            continue
        haystack = f"{name} {description}".lower()
        score = sum(1 for token in text_tokens if token in haystack)
        if not score:
            continue
        scored.append(
            (
                float(score),
                KnowledgeHit(
                    source=f"web/{SOURCE_NAME}",
                    scope="",
                    key=attack_id,
                    title=f"{attack_id}: {name}",
                    summary=description[:280],
                    value=description,
                    score=float(score),
                    extra={"category": category},
                ),
            )
        )
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [pair[1] for pair in scored[:limit]]


def _tokens(query: str, keywords: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = []
    for source in (query, *keywords):
        for token in (source or "").lower().split():
            token = token.strip(".,;:'\"()[]{}")
            if len(token) >= 4 and token not in out:
                out.append(token)
    return tuple(out[:24])
