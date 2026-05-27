"""Intelligence subsystem.

Replaces the legacy `rag` package with a layered, file-backed memory plus
optional networked cybersecurity retrieval. The aggregator preserves the
`knowledge_augmentation` contract used by the planner prompt while internally
sourcing hits from durable cross-run memory and (when explicitly enabled)
opt-in web sources (NVD CVE feeds, MITRE ATT&CK, Exploit-DB).
"""

from killchain_docker.intelligence.augmenter import (
    IntelligenceAugmenter,
    IntelligenceContext,
    KnowledgeHit,
)
from killchain_docker.intelligence.config import (
    KNOWLEDGE_MODE_DISABLED,
    KNOWLEDGE_MODE_ENABLED,
    KNOWLEDGE_MODE_OFFLINE,
    knowledge_mode,
)
from killchain_docker.intelligence.policy import KnowledgePolicy
from killchain_docker.intelligence.status import public_knowledge_payload

__all__ = [
    "IntelligenceAugmenter",
    "IntelligenceContext",
    "KnowledgeHit",
    "KnowledgePolicy",
    "KNOWLEDGE_MODE_DISABLED",
    "KNOWLEDGE_MODE_ENABLED",
    "KNOWLEDGE_MODE_OFFLINE",
    "knowledge_mode",
    "public_knowledge_payload",
]
