"""Tests for the durable-memory recall selector.

Covers the ``select_records`` deterministic-fallback path and the LLM-delegated
path, plus the scope priority that prefers category-scoped lessons over
global-scoped ones.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

from killchain_docker.intelligence.memdir.recall import (
    RecallQuery,
    select_records,
)
from killchain_docker.memory.durable import DurableMemoryRecord, DurableMemoryScope


def _record(
    slug: str,
    *,
    key: str | None = None,
    value: str = "",
    title: str = "",
    scope: DurableMemoryScope = DurableMemoryScope.CATEGORY,
    category: str | None = "crypto",
) -> DurableMemoryRecord:
    return DurableMemoryRecord(
        slug=slug,
        key=key or slug,
        value=value,
        scope=scope,
        category=category if scope != DurableMemoryScope.GLOBAL else None,
        title=title or slug,
    )


class SelectRecordsTests(unittest.TestCase):
    def test_empty_records_returns_empty(self) -> None:
        result = select_records(
            [],
            query=RecallQuery(objective="o", category="crypto"),
            limit=3,
        )
        self.assertEqual(result, [])

    def test_zero_limit_returns_empty(self) -> None:
        result = select_records(
            [_record("a", value="lfsr cipher")],
            query=RecallQuery(objective="o", category="crypto"),
            limit=0,
        )
        self.assertEqual(result, [])

    def test_deterministic_select_prefers_keyword_overlap(self) -> None:
        records = [
            _record("noise", value="unrelated lesson about scanning"),
            _record("good", value="lfsr cipher recovery via known plaintext"),
        ]
        result = select_records(
            records,
            query=RecallQuery(
                objective="recover the LFSR cipher",
                category="crypto",
                keywords=("lfsr",),
            ),
            limit=1,
        )
        self.assertEqual([r.slug for r in result], ["good"])

    def test_deterministic_select_breaks_ties_by_input_order(self) -> None:
        records = [
            _record("first", value="generic note"),
            _record("second", value="generic note"),
        ]
        result = select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=2,
        )
        # Same scope, no keyword overlap — earlier index wins the tiebreak so
        # callers can rely on a stable ordering when relevance is equal.
        self.assertEqual([r.slug for r in result], ["first", "second"])

    def test_category_scope_outranks_global_when_overlap_equal(self) -> None:
        records = [
            _record(
                "global-note",
                value="generic banner",
                scope=DurableMemoryScope.GLOBAL,
            ),
            _record(
                "category-note",
                value="generic banner",
                scope=DurableMemoryScope.CATEGORY,
            ),
        ]
        result = select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=1,
        )
        self.assertEqual([r.slug for r in result], ["category-note"])

    def test_llm_delegate_path_uses_returned_slugs(self) -> None:
        records = [_record(f"r{i}", value=f"lesson {i}") for i in range(8)]
        decision = MagicMock()
        decision.selected_slugs = ["r3", "r5"]
        llm = MagicMock()
        llm.generate_json.return_value = decision
        result = select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=2,
            llm_client=llm,
        )
        self.assertEqual([r.slug for r in result], ["r3", "r5"])
        llm.generate_json.assert_called_once()

    def test_llm_delegate_path_falls_back_when_llm_fails(self) -> None:
        from killchain_docker.llm.gateway import LLMClientError

        records = [_record(f"r{i}", value=f"lesson {i}") for i in range(8)]
        llm = MagicMock()
        llm.generate_json.side_effect = LLMClientError("offline")
        result = select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=3,
            llm_client=llm,
        )
        self.assertEqual(len(result), 3)
        self.assertTrue(all(isinstance(r, DurableMemoryRecord) for r in result))

    def test_llm_delegate_ignores_invented_slugs(self) -> None:
        records = [_record(f"r{i}", value=f"lesson {i}") for i in range(8)]
        decision = MagicMock()
        decision.selected_slugs = ["does-not-exist", "r2"]
        llm = MagicMock()
        llm.generate_json.return_value = decision
        result = select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=2,
            llm_client=llm,
        )
        self.assertEqual([r.slug for r in result], ["r2"])

    def test_small_record_set_skips_llm(self) -> None:
        records = [_record("a", value="x"), _record("b", value="y")]
        llm = MagicMock()
        select_records(
            records,
            query=RecallQuery(objective="o", category="crypto"),
            limit=2,
            llm_client=llm,
        )
        llm.generate_json.assert_not_called()


if __name__ == "__main__":
    unittest.main()
