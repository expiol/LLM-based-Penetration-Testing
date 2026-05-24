from __future__ import annotations

import io
import json
import logging
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from killchain_docker.logging_utils import (
    ContextFormatter,
    DEFAULT_LOG_FORMAT,
    JsonFormatter,
    json_dumps,
    json_sanitize,
    safe_extra,
    write_json_file,
    write_jsonl_file,
    write_text_file,
)


class LoggingUtilsTests(unittest.TestCase):
    def test_context_formatter_renders_extra_fields(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(ContextFormatter("%(levelname)s:%(name)s:%(message)s"))
        logger = logging.getLogger("tests.context_formatter")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        logger.info("hello", extra={"challenge": "alpha", "run_id": "run-1"})

        output = stream.getvalue()
        self.assertIn("INFO:tests.context_formatter:hello", output)
        self.assertIn('"challenge": "alpha"', output)
        self.assertIn('"run_id": "run-1"', output)
        self.assertNotIn('"message"', output)
        self.assertNotIn('"asctime"', output)

    def test_context_formatter_handles_circular_extra_fields(self) -> None:
        payload: dict[str, object] = {"name": "root"}
        payload["self"] = payload
        record = logging.LogRecord(
            name="tests.context_formatter",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.payload = payload  # type: ignore[attr-defined]

        output = ContextFormatter("%(message)s").format(record)

        self.assertIn('"payload": {"name": "root", "self": "[circular]"}', output)

    def test_default_text_format_includes_process_and_thread_fields(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(ContextFormatter(DEFAULT_LOG_FORMAT))
        logger = logging.getLogger("tests.default_formatter")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        logger.info("hello")

        output = stream.getvalue()
        self.assertIn("pid=", output)
        self.assertIn("thread=", output)
        self.assertIn("thread_id=", output)

    def test_json_formatter_renders_exception_traceback(self) -> None:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(JsonFormatter())
        logger = logging.getLogger("tests.json_formatter")
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.INFO)

        try:
            raise RuntimeError("boom")
        except RuntimeError:
            logger.exception("failed", extra={"stage": "unit"})

        payload = json.loads(stream.getvalue())
        self.assertEqual(payload["level"], "ERROR")
        self.assertEqual(payload["message"], "failed")
        self.assertIsInstance(payload["pid"], int)
        self.assertIsInstance(payload["thread_id"], int)
        self.assertIsInstance(payload["thread_name"], str)
        self.assertEqual(payload["context"]["stage"], "unit")
        self.assertIn("RuntimeError: boom", payload["traceback"])

    def test_json_formatter_handles_circular_extra_fields(self) -> None:
        payload: dict[str, object] = {"name": "root"}
        payload["self"] = payload
        record = logging.LogRecord(
            name="tests.json_formatter",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.payload = payload  # type: ignore[attr-defined]

        output = json.loads(JsonFormatter().format(record))

        self.assertEqual(
            output["context"]["payload"],
            {"name": "root", "self": "[circular]"},
        )

    def test_safe_extra_drops_reserved_record_keys(self) -> None:
        self.assertEqual(
            safe_extra({"message": "reserved", "challenge": "alpha"}),
            {"challenge": "alpha"},
        )

    def test_safe_extra_drops_private_and_non_string_keys(self) -> None:
        self.assertEqual(
            safe_extra({1: "bad", "_private": "bad", "challenge": "alpha"}),  # type: ignore[dict-item]
            {"challenge": "alpha"},
        )

    def test_safe_extra_sanitizes_values(self) -> None:
        payload: dict[str, object] = {"path": Path("/tmp/demo")}
        payload["self"] = payload

        self.assertEqual(
            safe_extra({"payload": payload}),
            {"payload": {"path": "/tmp/demo", "self": "[circular]"}},
        )

    def test_formatters_ignore_non_string_record_keys(self) -> None:
        record = logging.LogRecord(
            name="tests.record",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="hello",
            args=(),
            exc_info=None,
        )
        record.__dict__[1] = "bad"
        record.__dict__["challenge"] = "alpha"

        text = ContextFormatter("%(message)s").format(record)
        payload = json.loads(JsonFormatter().format(record))

        self.assertIn('"challenge": "alpha"', text)
        self.assertEqual(payload["context"], {"challenge": "alpha"})

    def test_json_file_helpers_stringify_non_json_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "artifact.bin"
            json_path = root / "payload.json"
            jsonl_path = root / "payload.jsonl"

            write_json_file(json_path, {"path": marker})
            write_jsonl_file(jsonl_path, [{"path": marker}])

            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8"))["path"],
                str(marker),
            )
            self.assertEqual(
                json.loads(jsonl_path.read_text(encoding="utf-8").strip())["path"],
                str(marker),
            )

    def test_json_file_helpers_handle_circular_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            payload: dict[str, object] = {"name": "root"}
            payload["self"] = payload
            json_path = root / "payload.json"
            jsonl_path = root / "payload.jsonl"

            write_json_file(json_path, payload)
            write_jsonl_file(jsonl_path, [payload])

            self.assertEqual(
                json.loads(json_path.read_text(encoding="utf-8")),
                {"name": "root", "self": "[circular]"},
            )
            self.assertEqual(
                json.loads(jsonl_path.read_text(encoding="utf-8").strip()),
                {"name": "root", "self": "[circular]"},
            )

    def test_json_dumps_handles_circular_payloads(self) -> None:
        payload: dict[str, object] = {"name": "root"}
        payload["self"] = payload

        self.assertEqual(
            json.loads(json_dumps(payload)),
            {"name": "root", "self": "[circular]"},
        )

    def test_json_sanitize_returns_json_compatible_copy(self) -> None:
        payload = {"path": Path("/tmp/demo"), "items": [Path("/tmp/other")]}

        self.assertEqual(
            json_sanitize(payload),
            {"items": ["/tmp/other"], "path": "/tmp/demo"},
        )

    def test_json_sanitize_handles_circular_references(self) -> None:
        payload: dict[str, object] = {"name": "root"}
        payload["self"] = payload

        self.assertEqual(
            json_sanitize(payload),
            {"name": "root", "self": "[circular]"},
        )

    def test_atomic_file_helpers_support_concurrent_same_path_writes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "payload.json"
            text_path = root / "payload.txt"

            def write_pair(index: int) -> None:
                write_json_file(json_path, {"index": index})
                write_text_file(text_path, f"{index}\n")

            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(write_pair, index) for index in range(80)]
                for future in futures:
                    future.result()

            self.assertIn(json.loads(json_path.read_text(encoding="utf-8"))["index"], range(80))
            self.assertIn(int(text_path.read_text(encoding="utf-8").strip()), range(80))
            self.assertEqual(list(root.glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
