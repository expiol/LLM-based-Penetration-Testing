"""Tests for the networked-intelligence web layer.

Covers the policy gates that keep benchmark identifiers out of outbound
queries, plus the parsing fallbacks for the three public security sources
(NVD, MITRE ATT&CK, Exploit-DB).
"""

from __future__ import annotations

import unittest

from killchain_docker.intelligence.web.policy import (
    ALLOWED_HOSTS,
    host_allowed,
    redact_query,
)
from killchain_docker.intelligence.web.sources import mitre_attack, nvd


class HostAllowlistTests(unittest.TestCase):
    def test_known_hosts_pass(self) -> None:
        for host in ALLOWED_HOSTS:
            self.assertTrue(host_allowed(host), host)

    def test_subdomains_pass(self) -> None:
        self.assertTrue(host_allowed("api.services.nvd.nist.gov"))

    def test_unknown_hosts_blocked(self) -> None:
        self.assertFalse(host_allowed("evil.example.com"))
        self.assertFalse(host_allowed("nvd.nist.gov.evil.com"))


class RedactQueryTests(unittest.TestCase):
    def test_strips_flag_literal(self) -> None:
        result = redact_query("flag{leaked-secret} crypto cipher")
        self.assertNotIn("flag{", result.query)
        self.assertNotIn("leaked-secret", result.query)
        self.assertIn("flag_literal", result.redactions)

    def test_strips_challenge_phrase(self) -> None:
        result = redact_query("look up challenge-stfu writeup")
        self.assertNotIn("challenge-stfu", result.query)
        self.assertIn("challenge_name", result.redactions)

    def test_strips_blocked_tokens(self) -> None:
        result = redact_query(
            "research SecretChallengeName CSAW2023 cipher",
            blocked_tokens=("SecretChallengeName", "CSAW2023"),
        )
        self.assertNotIn("SecretChallengeName", result.query)
        self.assertNotIn("CSAW2023", result.query)
        self.assertTrue(any(r.startswith("blocked:") for r in result.redactions))

    def test_collapses_whitespace(self) -> None:
        result = redact_query(
            "  multiple   spaces  flag{x} after  ",
        )
        self.assertEqual(result.query.count("  "), 0)

    def test_safe_query_passes_through(self) -> None:
        result = redact_query("LFSR cipher recovery technique")
        self.assertEqual(result.query, "LFSR cipher recovery technique")
        self.assertEqual(result.redactions, ())

    def test_empty_blocked_tokens_skipped(self) -> None:
        result = redact_query("xss in form", blocked_tokens=("", "  "))
        self.assertEqual(result.query, "xss in form")
        self.assertEqual(result.redactions, ())


class NvdSourceTests(unittest.TestCase):
    def _fetch(self, payload: dict[str, object]):
        def fake_fetch(_url, **_kwargs):
            return payload
        return fake_fetch

    def test_returns_typed_hits(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [
                            {"lang": "en", "value": "Buffer overflow in foo."},
                            {"lang": "es", "value": "Ignored."},
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.8}}
                            ]
                        },
                    }
                }
            ]
        }
        hits = nvd.search(
            query="buffer overflow",
            category="pwn",
            keywords=("buffer",),
            fetch_json=self._fetch(payload),
            limit=2,
        )
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit.key, "CVE-2024-1234")
        self.assertEqual(hit.source, "web/nvd")
        self.assertIn("Buffer overflow", hit.summary)
        self.assertEqual(hit.score, 9.8)

    def test_empty_query_returns_empty(self) -> None:
        hits = nvd.search(
            query="",
            category="pwn",
            keywords=(),
            fetch_json=self._fetch({"vulnerabilities": []}),
        )
        self.assertEqual(hits, [])

    def test_malformed_payload_returns_empty(self) -> None:
        hits = nvd.search(
            query="x",
            category="pwn",
            keywords=("x",),
            fetch_json=self._fetch({"vulnerabilities": "not-a-list"}),
        )
        self.assertEqual(hits, [])

    def test_skips_entries_without_id(self) -> None:
        payload = {
            "vulnerabilities": [
                {"cve": {"id": "", "descriptions": []}},
                {"cve": {"id": "CVE-2024-9999", "descriptions": []}},
            ]
        }
        hits = nvd.search(
            query="x",
            category="pwn",
            keywords=("x",),
            fetch_json=self._fetch(payload),
        )
        self.assertEqual([h.key for h in hits], ["CVE-2024-9999"])


class MitreAttackSourceTests(unittest.TestCase):
    def _bundle(self) -> dict[str, object]:
        return {
            "objects": [
                {
                    "type": "attack-pattern",
                    "name": "OS Command Injection",
                    "description": "Adversaries inject OS commands via user input.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "name": "Data Encoding",
                    "description": "Adversaries encode data to evade detection.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1132"}
                    ],
                },
                {
                    "type": "attack-pattern",
                    "name": "Deprecated Tactic",
                    "description": "Should be skipped.",
                    "x_mitre_deprecated": True,
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T9999"}
                    ],
                },
                {"type": "intrusion-set", "name": "Ignored"},
            ]
        }

    def test_returns_matching_attack_patterns(self) -> None:
        def fake_fetch(_url, **_kwargs):
            return self._bundle()

        hits = mitre_attack.search(
            query="command injection",
            category="web",
            keywords=("injection",),
            fetch_json=fake_fetch,
        )
        keys = [h.key for h in hits]
        self.assertIn("T1059", keys)
        self.assertNotIn("T9999", keys)

    def test_drops_deprecated_revoked_and_non_pattern_entries(self) -> None:
        bundle = self._bundle()
        bundle["objects"].append(  # type: ignore[union-attr]
            {
                "type": "attack-pattern",
                "name": "Revoked Tactic",
                "description": "encoding",
                "revoked": True,
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T8888"}
                ],
            }
        )

        def fake_fetch(_url, **_kwargs):
            return bundle

        hits = mitre_attack.search(
            query="encoding",
            category="misc",
            keywords=("encoding",),
            fetch_json=fake_fetch,
        )
        keys = [h.key for h in hits]
        self.assertIn("T1132", keys)
        self.assertNotIn("T8888", keys)
        self.assertNotIn("T9999", keys)

    def test_short_keywords_drop_below_token_floor(self) -> None:
        # Tokens shorter than 4 chars are dropped; an all-short query can
        # legitimately produce no hits.
        def fake_fetch(_url, **_kwargs):
            return self._bundle()

        hits = mitre_attack.search(
            query="os ip",
            category="misc",
            keywords=("a", "b"),
            fetch_json=fake_fetch,
        )
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
