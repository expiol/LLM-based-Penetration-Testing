"""Regression: Pydantic LLM-guidance schemas tolerate common JSON quirks."""

from __future__ import annotations

import unittest

from killchain_docker.reasoning.coercion import coerce_llm_bool


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

    def test_bool_passthrough(self) -> None:
        self.assertIs(coerce_llm_bool(True), True)
        self.assertIs(coerce_llm_bool(False), False)

    def test_none_is_false(self) -> None:
        self.assertIs(coerce_llm_bool(None), False)


if __name__ == "__main__":
    unittest.main()
