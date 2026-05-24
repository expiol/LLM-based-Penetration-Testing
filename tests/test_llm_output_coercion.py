"""Regression: Pydantic LLM-guidance schemas tolerate common JSON quirks."""

from __future__ import annotations

import unittest
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from pydantic import BaseModel

from killchain_docker.llm.gateway import (
    GatewayLLMClient,
    LLMClientError,
    LLMFailureKind,
    LLMSettings,
    StaticLLMClient,
    TokenLedger,
    build_llm_client_from_env,
)
from killchain_docker.llm.structured_output import (
    close_array_before_object_field,
    loads_lenient_json_object,
    python_string_literal_after,
)
from killchain_docker.orchestrator.planning.schemas import PlannerDecision
from killchain_docker.reasoning.coercion import coerce_llm_bool
from killchain_docker.reasoning.schemas import ToolUseDecision


class _RequiredPayload(BaseModel):
    name: str


class _DeadlineGateway(GatewayLLMClient):
    def __init__(self, *, fail: bool = False, total_deadline_s: int | None = 5) -> None:
        self.default_model = "test-model"
        self.schema_models = {}
        self.timeout_s = 20
        self.max_retries = 3
        self.total_deadline_s = total_deadline_s
        self.max_completion_tokens = 128
        self.request_timeouts: list[float | None] = []
        self.fail = fail

    def _create_structured(
        self,
        *,
        messages,
        schema,
        model,
        temperature,
        request_timeout_s=None,
    ):
        del messages, schema, model, temperature
        self.request_timeouts.append(request_timeout_s)
        if self.fail:
            raise ConnectionError("Connection error.")
        return _RequiredPayload(name="ok"), None

    def _record_usage(self, completion, **_kwargs) -> None:
        del completion


class _UsageCompletion:
    model = "completion-model"
    usage = {"prompt_tokens": 11, "completion_tokens": 7}


class _UsageGateway(_DeadlineGateway):
    def __init__(self, *, completion=None) -> None:
        super().__init__(fail=False, total_deadline_s=5)
        self.token_ledger = TokenLedger()
        self.completion = completion

    def _create_structured(
        self,
        *,
        messages,
        schema,
        model,
        temperature,
        request_timeout_s=None,
    ):
        del messages, schema, model, temperature, request_timeout_s
        return _RequiredPayload(name="ok"), self.completion

    def _record_usage(self, completion, **kwargs) -> None:
        GatewayLLMClient._record_usage(self, completion, **kwargs)


class _HangingGateway(_DeadlineGateway):
    def __init__(self) -> None:
        super().__init__(fail=False, total_deadline_s=1)
        self.timeout_s = 1
        self.max_retries = 0

    def _create_structured(
        self,
        *,
        messages,
        schema,
        model,
        temperature,
        request_timeout_s=None,
    ):
        self.request_timeouts.append(request_timeout_s)
        time.sleep(5)
        return _RequiredPayload(name="late"), None


class _PreflightClient:
    def __init__(self) -> None:
        self.preflight_called = False

    def preflight(self) -> None:
        self.preflight_called = True


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

    def test_generate_json_passes_remaining_deadline_to_request(self) -> None:
        client = _DeadlineGateway(total_deadline_s=5)

        result = client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertEqual(result.name, "ok")
        assert client.request_timeouts[0] is not None
        self.assertLessEqual(client.request_timeouts[0], 5.0)
        self.assertGreater(client.request_timeouts[0], 0.0)

    def test_generate_json_usage_log_is_structured(self) -> None:
        client = _UsageGateway(completion=_UsageCompletion())

        with self.assertLogs("killchain_docker.llm.gateway", level="INFO") as captured:
            result = client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertEqual(result.name, "ok")
        self.assertEqual(client.token_ledger.to_dict()["total_tokens"], 18)
        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.getMessage(), "LLM call completed")
        self.assertEqual(record.schema, "_RequiredPayload")
        self.assertEqual(record.model, "completion-model")
        self.assertEqual(record.llm_call, 1)
        self.assertEqual(record.prompt_tokens, 11)
        self.assertEqual(record.completion_tokens, 7)
        self.assertEqual(record.total_tokens, 18)
        self.assertTrue(record.usage_available)

    def test_generate_json_usage_log_marks_missing_usage(self) -> None:
        client = _UsageGateway(completion=None)

        with self.assertLogs("killchain_docker.llm.gateway", level="INFO") as captured:
            client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertEqual(client.token_ledger.to_dict()["total_tokens"], 0)
        record = captured.records[0]
        self.assertEqual(record.getMessage(), "LLM call completed")
        self.assertEqual(record.model, "test-model")
        self.assertEqual(record.prompt_tokens, 0)
        self.assertEqual(record.completion_tokens, 0)
        self.assertEqual(record.total_tokens, 0)
        self.assertFalse(record.usage_available)

    def test_token_ledger_records_thread_safe_snapshots(self) -> None:
        ledger = TokenLedger()

        def record_many() -> None:
            for _ in range(500):
                ledger.record(2, 3)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda _worker: record_many(), range(8)))

        self.assertEqual(
            ledger.to_dict(),
            {
                "llm_calls": 4000,
                "prompt_tokens": 8000,
                "completion_tokens": 12000,
                "total_tokens": 20000,
            },
        )

    def test_generate_json_stops_retry_when_total_deadline_cannot_fit_backoff(self) -> None:
        client = _DeadlineGateway(fail=True, total_deadline_s=1)

        with self.assertRaises(LLMClientError) as ctx:
            client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertEqual(ctx.exception.attempts, 1)
        self.assertEqual(len(client.request_timeouts), 1)
        assert client.request_timeouts[0] is not None
        self.assertLessEqual(client.request_timeouts[0], 1.0)

    def test_transient_retry_log_includes_context_and_traceback(self) -> None:
        client = _DeadlineGateway(fail=True, total_deadline_s=10)
        client.max_retries = 1

        with (
            patch("killchain_docker.llm.gateway.random.uniform", return_value=0.0),
            patch("killchain_docker.llm.gateway.time.sleep"),
            self.assertLogs("killchain_docker.llm.gateway", level="WARNING") as captured,
        ):
            with self.assertRaises(LLMClientError):
                client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        retry_records = [
            record
            for record in captured.records
            if record.getMessage() == "gateway transient error; retrying"
        ]
        self.assertEqual(len(retry_records), 1)
        record = retry_records[0]
        self.assertEqual(record.schema, "_RequiredPayload")
        self.assertEqual(record.model, "test-model")
        self.assertEqual(record.error_type, "ConnectionError")
        self.assertTrue(any("Traceback" in message for message in captured.output))

    def test_generate_json_final_failure_log_includes_context_and_traceback(self) -> None:
        client = _DeadlineGateway(fail=True, total_deadline_s=1)

        with self.assertLogs("killchain_docker.llm.gateway", level="ERROR") as captured:
            with self.assertRaises(LLMClientError):
                client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertEqual(len(captured.records), 1)
        record = captured.records[0]
        self.assertEqual(record.getMessage(), "gateway structured output failed")
        self.assertEqual(record.schema, "_RequiredPayload")
        self.assertEqual(record.model, "test-model")
        self.assertEqual(record.failure_kind, "connection")
        self.assertEqual(record.error_type, "ConnectionError")
        self.assertEqual(record.attempts, 1)
        self.assertTrue(any("Traceback" in message for message in captured.output))

    def test_build_llm_client_from_env_constructs_gateway_before_preflight(self) -> None:
        fake_client = _PreflightClient()
        settings = LLMSettings(
            provider="openai_compatible",
            api_key="test-key",
            model="test-model",
            timeout_s=180,
            max_retries=5,
            total_deadline_s=300,
        )

        with (
            patch("killchain_docker.llm.gateway.LLMSettings.from_env", return_value=settings),
            patch("killchain_docker.llm.gateway.GatewayLLMClient", return_value=fake_client) as gateway_cls,
        ):
            client = build_llm_client_from_env(preflight=True)

        self.assertIs(client, fake_client)
        self.assertTrue(fake_client.preflight_called)
        self.assertEqual(gateway_cls.call_args.kwargs["total_deadline_s"], 300)

    def test_llm_settings_rejects_invalid_numeric_config_as_config_error(self) -> None:
        payload = {
            "provider": "openai_compatible",
            "api_key": "test-key",
            "default_model": "test-model",
            "timeout_s": "later",
        }

        with patch("killchain_docker.llm.gateway._load_runtime_config_payload", return_value=payload):
            with self.assertRaises(LLMClientError) as ctx:
                LLMSettings.from_env()

        self.assertEqual(ctx.exception.kind, LLMFailureKind.CONFIG)

    def test_llm_settings_rejects_out_of_range_numeric_config_as_config_error(self) -> None:
        payload = {
            "provider": "openai_compatible",
            "api_key": "test-key",
            "default_model": "test-model",
            "max_retries": -1,
        }

        with patch("killchain_docker.llm.gateway._load_runtime_config_payload", return_value=payload):
            with self.assertRaises(LLMClientError) as ctx:
                LLMSettings.from_env()

        self.assertEqual(ctx.exception.kind, LLMFailureKind.CONFIG)

    def test_generate_json_hard_deadline_interrupts_blocking_request(self) -> None:
        client = _HangingGateway()
        started = time.monotonic()

        with self.assertRaises(LLMClientError) as ctx:
            client.generate_json(system_prompt="", user_prompt="", schema=_RequiredPayload)

        self.assertLess(time.monotonic() - started, 3.0)
        self.assertEqual(ctx.exception.kind, LLMFailureKind.TIMEOUT)
        self.assertEqual(ctx.exception.attempts, 1)


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

    def test_static_client_does_not_repair_missing_quote_by_schema_field_name(self) -> None:
        payload = """{
  "capability": "script.exec",
  "metadata": {
    "script_code": "print('alpha')
  },
  "rationale": "run script",
  "expected_signal": "stdout"
}"""
        client = StaticLLMClient([payload])

        with self.assertRaises(LLMClientError):
            client.generate_json(
                system_prompt="",
                user_prompt="",
                schema=ToolUseDecision,
            )

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

    def test_decoder_closes_array_before_next_object_field(self) -> None:
        payload = """{
  "summary": "retry plan",
  "todos": [],
  "notes": ["first note", "second note", "stop_run": false
}"""

        decoded = loads_lenient_json_object(payload)

        self.assertEqual(decoded["notes"], ["first note", "second note"])
        self.assertIs(decoded["stop_run"], False)

    def test_decoder_closes_array_before_arbitrary_object_field(self) -> None:
        payload = """{
  "items": ["alpha", "beta", "schema_renamed_field": 42
}"""

        decoded = loads_lenient_json_object(payload)

        self.assertEqual(decoded["items"], ["alpha", "beta"])
        self.assertEqual(decoded["schema_renamed_field"], 42)

    def test_array_repair_ignores_valid_array_entries(self) -> None:
        payload = '{"items": ["alpha", "beta"]}'

        self.assertEqual(close_array_before_object_field(payload), payload)

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

    def test_gateway_recovers_planner_completion_with_missing_notes_array_close(self) -> None:
        client = object.__new__(GatewayLLMClient)
        exc = ValueError(
            "InstructorRetryException: ChatCompletionMessage("
            "content='{\\n"
            "  \"summary\": \"retry plan\",\\n"
            "  \"todos\": [],\\n"
            "  \"notes\": [\"first note\", \"second note\", \"stop_run\": false\\n"
            "}', refusal=None, role='assistant')"
        )

        recovered = client._recover_structured_from_exception(exc, PlannerDecision)

        self.assertIsNotNone(recovered)
        assert recovered is not None
        decision, _completion = recovered
        self.assertEqual(decision.notes, ["first note", "second note"])
        self.assertFalse(decision.stop_run)


if __name__ == "__main__":
    unittest.main()
