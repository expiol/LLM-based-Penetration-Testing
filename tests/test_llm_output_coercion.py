"""Regression: Pydantic LLM-guidance schemas tolerate common JSON quirks."""

from __future__ import annotations

import unittest

from killchain_docker.workers._helpers.coercion import coerce_llm_bool
from killchain_docker.reasoning.schemas import (
    EvidenceReviewGuidance,
    ScriptCodeGuidance,
)


class TestCoerceLlmBool(unittest.TestCase):
    def test_empty_container_is_false(self) -> None:
        self.assertIs(coerce_llm_bool([]), False)
        self.assertIs(coerce_llm_bool({}), False)

    def test_nonempty_container_truthy_semantics(self) -> None:
        self.assertTrue(coerce_llm_bool([False]))
        self.assertTrue(coerce_llm_bool({"ok": False}))

    def test_string_sentinels(self) -> None:
        self.assertIs(coerce_llm_bool("true"), True)
        self.assertIs(coerce_llm_bool("no"), False)

    def test_evidence_promote_bool_fields(self) -> None:
        g = EvidenceReviewGuidance.model_validate(
            {
                "summary": "x",
                "promote_runtime_probe": [],
                "promote_computation_analysis": [1],
            }
        )
        self.assertFalse(g.promote_runtime_probe)
        self.assertTrue(g.promote_computation_analysis)

    def test_script_should_retry_bool_field(self) -> None:
        g = ScriptCodeGuidance.model_validate(
            {
                "summary": "s",
                "script_code": "print('ok')\n",
                "should_retry_on_failure": [],
            }
        )
        self.assertFalse(g.should_retry_on_failure)


if __name__ == "__main__":
    unittest.main()
