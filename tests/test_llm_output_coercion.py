"""Regression: Pydantic LLM-guidance schemas tolerate common JSON quirks."""

from __future__ import annotations

import unittest

from pydantic import BaseModel

from killchain_docker.llm.gateway import GatewayLLMClient
from killchain_docker.reasoning.coercion import coerce_llm_bool


class _RequiredPayload(BaseModel):
    name: str


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


class TestGatewayTransientClassification(unittest.TestCase):
    def test_validation_error_is_not_transient_even_with_connection_history(self) -> None:
        client = object.__new__(GatewayLLMClient)
        message = (
            "1 validation error for ToolUseDecision\n"
            "Value error, script.execute requires script_code\n"
            "previous failed attempt: Connection error."
        )

        self.assertFalse(client._is_transient(ValueError(message)))

    def test_pydantic_validation_error_is_not_transient(self) -> None:
        client = object.__new__(GatewayLLMClient)
        try:
            _RequiredPayload.model_validate({})
        except Exception as exc:
            validation_error = exc
        else:  # pragma: no cover
            self.fail("expected validation error")

        self.assertFalse(client._is_transient(validation_error))

    def test_network_errors_remain_transient(self) -> None:
        client = object.__new__(GatewayLLMClient)

        self.assertTrue(client._is_transient(ConnectionError("Connection error.")))
        self.assertTrue(client._is_transient(TimeoutError("timed out")))


if __name__ == "__main__":
    unittest.main()
