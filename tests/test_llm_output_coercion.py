"""Regression: Pydantic LLM-guidance schemas tolerate common JSON quirks."""

from __future__ import annotations

import unittest

from pydantic import BaseModel

from killchain_docker.llm.gateway import (
    GatewayLLMClient,
    LLMClientError,
    LLMFailureKind,
    StaticLLMClient,
)
from killchain_docker.llm.structured_output import (
    loads_lenient_json_object,
    python_string_literal_after,
)
from killchain_docker.reasoning.coercion import coerce_llm_bool
from killchain_docker.reasoning.schemas import ToolUseDecision


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
        self.assertEqual(
            client._classify_failure(ValueError(message)),
            LLMFailureKind.SCHEMA_VALIDATION,
        )

    def test_pydantic_validation_error_is_not_transient(self) -> None:
        client = object.__new__(GatewayLLMClient)
        try:
            _RequiredPayload.model_validate({})
        except Exception as exc:
            validation_error = exc
        else:  # pragma: no cover
            self.fail("expected validation error")

        self.assertFalse(client._is_transient(validation_error))
        self.assertEqual(
            client._classify_failure(validation_error),
            LLMFailureKind.SCHEMA_VALIDATION,
        )

    def test_network_errors_remain_transient(self) -> None:
        client = object.__new__(GatewayLLMClient)

        self.assertTrue(client._is_transient(ConnectionError("Connection error.")))
        self.assertTrue(client._is_transient(TimeoutError("timed out")))
        self.assertEqual(
            client._classify_failure(ConnectionError("Connection error.")),
            LLMFailureKind.CONNECTION,
        )
        self.assertEqual(
            client._classify_failure(TimeoutError("timed out")),
            LLMFailureKind.TIMEOUT,
        )

    def test_client_error_carries_typed_failure_metadata(self) -> None:
        exc = LLMClientError(
            "structured output failed",
            kind=LLMFailureKind.SCHEMA_VALIDATION,
            schema_name="ToolUseDecision",
            model="test-model",
            attempts=3,
        )

        self.assertFalse(exc.transient)
        self.assertEqual(exc.kind, LLMFailureKind.SCHEMA_VALIDATION)
        self.assertEqual(exc.schema_name, "ToolUseDecision")
        self.assertEqual(exc.model, "test-model")
        self.assertEqual(exc.attempts, 3)


class TestLenientStructuredOutput(unittest.TestCase):
    def test_decoder_repairs_bare_newline_without_gateway_client(self) -> None:
        payload = """{
  "script_code": "print('alpha
beta')"
}"""

        decoded = loads_lenient_json_object(payload)

        self.assertEqual(decoded["script_code"], "print('alpha\nbeta')")

    def test_decoder_recovers_content_literal_from_exception_text(self) -> None:
        text = "InstructorRetryException(content='{\\n  \"ok\": true\\n}', retries=2)"

        self.assertEqual(python_string_literal_after(text, "content="), '{\n  "ok": true\n}')

    def test_static_client_repairs_bare_newline_in_json_string(self) -> None:
        payload = """{
  "capability": "script.exec",
  "metadata": {
    "script_code": "print('alpha
beta')"
  },
  "rationale": "run script",
  "expected_signal": "stdout"
}"""
        client = StaticLLMClient([payload])

        decision = client.generate_json(
            system_prompt="",
            user_prompt="",
            schema=ToolUseDecision,
        )

        self.assertEqual(decision.capability, "script.exec")
        self.assertEqual(decision.metadata["script_code"], "print('alpha\nbeta')")

    def test_static_client_repairs_missing_string_quote_before_metadata_boundary(self) -> None:
        payload = """{
  "capability": "script.exec",
  "metadata": {
    "script_code": "print('alpha')
  },
  "rationale": "run script",
  "expected_signal": "stdout"
}"""
        client = StaticLLMClient([payload])

        decision = client.generate_json(
            system_prompt="",
            user_prompt="",
            schema=ToolUseDecision,
        )

        self.assertEqual(decision.metadata["script_code"], "print('alpha')")

    def test_static_client_repairs_source_code_backslash_escapes(self) -> None:
        payload = r"""{
  "capability": "script.exec",
  "metadata": {
    "script_code": "import re\npat = re.compile('\bcmp\w+')"
  },
  "rationale": "inspect disassembly",
  "expected_signal": "matching cmp instructions"
}"""
        client = StaticLLMClient([payload])

        decision = client.generate_json(
            system_prompt="",
            user_prompt="",
            schema=ToolUseDecision,
        )

        self.assertEqual(
            decision.metadata["script_code"],
            "import re\npat = re.compile('\\bcmp\\w+')",
        )

    def test_gateway_recovers_completion_embedded_in_instructor_error(self) -> None:
        client = object.__new__(GatewayLLMClient)
        exc = ValueError(
            "InstructorRetryException: ChatCompletionMessage("
            "content='{\\n  \"capability\": \"script.exec\",\\n  \"metadata\": {"
            "\\n    \"script_code\": \"print(\\'alpha\\nbeta\\')\"\\n  },"
            "\\n  \"rationale\": \"run script\",\\n  \"expected_signal\": \"stdout\"\\n}', "
            "refusal=None, role='assistant')"
        )

        recovered = client._recover_structured_from_exception(exc, ToolUseDecision)

        self.assertIsNotNone(recovered)
        assert recovered is not None
        decision, completion = recovered
        self.assertIsNone(completion)
        self.assertEqual(decision.metadata["script_code"], "print('alpha\nbeta')")


if __name__ == "__main__":
    unittest.main()
