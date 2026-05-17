"""Tests for the capability gateway with the new 2-plugin architecture."""

from __future__ import annotations

import unittest

from killchain_docker.state import RunState, TodoItem, WorkerResult
from killchain_docker.tools import (
    ExecutionMode,
    ExecutionPlane,
    ToolCapability,
    ToolExecutionRequest,
    ToolExecutionResult,
    ToolGateway,
)
from killchain_docker.tools.plugins.shell import build_output as shell_output_builder
from killchain_docker.tools.plugins.script import build_output as script_output_builder


class _StaticShellPlugin:
    mode = ExecutionMode.SIMULATED
    name = "shell_exec"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="flag{shell_test}\n",
        )


class _StaticScriptPlugin:
    mode = ExecutionMode.SIMULATED
    name = "script_exec"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout="flag{script_test}\n",
        )


class CapabilityGatewayTests(unittest.TestCase):
    def test_gateway_maps_shell_exec_capability(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticShellPlugin()
        plane.register(plugin, shell_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-1",
            capability=ToolCapability.SHELL_EXEC,
            metadata={"command": "echo flag{shell_test}"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.capability, ToolCapability.SHELL_EXEC.value)
        self.assertEqual(plugin.last_request.tool_name, "shell_exec")
        self.assertEqual(bundle.evidence.capability, ToolCapability.SHELL_EXEC.value)
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{shell_test}")

    def test_gateway_maps_script_exec_capability(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticScriptPlugin()
        plane.register(plugin, script_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-2",
            capability=ToolCapability.SCRIPT_EXEC,
            metadata={"script_code": "print('flag{script_test}')"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.tool_name, "script_exec")
        self.assertEqual(plugin.last_request.capability, "script.exec")
        self.assertEqual(bundle.state_delta.flag_candidates[0].value, "flag{script_test}")

    def test_state_delta_applies_to_run_state(self) -> None:
        plane = ExecutionPlane()
        plugin = _StaticShellPlugin()
        plane.register(plugin, shell_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-3",
            capability=ToolCapability.SHELL_EXEC,
            metadata={"command": "grep -r flag /tmp"},
        )

        state = RunState(objective="Solve.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Find flags"))
        state.apply_worker_result(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="recon-worker",
                success=True,
                summary=bundle.parsed.summary,
                state_delta=bundle.state_delta,
                evidence_updates=[bundle.evidence],
            )
        )
        self.assertEqual(len(state.flag_candidates), 1)


class _StaticCurlPlugin:
    """Simulated curl plugin that captures requests and returns canned HTTP response."""

    mode = ExecutionMode.SIMULATED
    name = "curl"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None
        self._sessions: dict[str, str] = {}

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        session_id = str(request.metadata.get("session_id") or "")
        cookie_header = ""
        if session_id:
            cookie_header = "Set-Cookie: session=abc123; Path=/\r\n"
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                f"HTTP/1.1 200 OK\r\n"
                f"Server: nginx/1.18\r\n"
                f"Content-Type: text/html\r\n"
                f"{cookie_header}"
                f"\r\n"
                f"<html><body>flag{{curl_session_test}}</body></html>\n"
            ),
        )


class CurlSessionTests(unittest.TestCase):
    """Tests for curl plugin session persistence and rich output parsing."""

    def test_curl_basic_request_emits_endpoint_and_route(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-1",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login"},
        )

        self.assertIsNotNone(plugin.last_request)
        self.assertEqual(plugin.last_request.tool_name, "curl")
        self.assertEqual(bundle.tool_output.status.value, "success")
        # Flag extracted from body
        self.assertTrue(any(
            fc.value == "flag{curl_session_test}"
            for fc in bundle.tool_output.flag_candidates
        ))
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        self.assertEqual(bundle.tool_output.endpoints[0].url, "http://target:8080")
        self.assertEqual(bundle.tool_output.endpoints[0].hostname, "target")
        self.assertEqual(bundle.tool_output.endpoints[0].status_code, 200)
        # Route emitted
        self.assertEqual(len(bundle.tool_output.routes), 1)
        self.assertEqual(bundle.tool_output.routes[0].url, "http://target:8080/login")
        self.assertEqual(bundle.tool_output.routes[0].path, "/login")
        self.assertEqual(bundle.tool_output.routes[0].method, "GET")
        # No session emitted (no session_id in metadata)
        self.assertEqual(len(bundle.tool_output.sessions), 0)

    def test_curl_session_id_emits_session_with_cookies(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-2",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login", "session_id": "web-recon"},
        )

        # Session emitted with cookie data
        self.assertEqual(len(bundle.tool_output.sessions), 1)
        sess = bundle.tool_output.sessions[0]
        self.assertEqual(sess.session_type, "http_cookie")
        self.assertEqual(sess.status, "active")
        self.assertEqual(sess.metadata["session_id"], "web-recon")
        self.assertIn("session=abc123", sess.metadata["cookies"][0])
        # Summary mentions session
        self.assertIn("[session:web-recon]", bundle.tool_output.summary)
        # output_context has cookies
        self.assertIn("set_cookies", bundle.tool_output.output_context)

    def test_curl_output_context_fields(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-3",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/api/data", "method": "POST"},
        )

        ctx = bundle.tool_output.output_context
        self.assertEqual(ctx["url"], "http://target:8080/api/data")
        self.assertEqual(ctx["method"], "POST")
        self.assertEqual(ctx["http_status"], 200)
        self.assertEqual(ctx["server"], "nginx/1.18")
        self.assertEqual(ctx["content_type"], "text/html")
        self.assertIn("POST", bundle.tool_output.summary)

    def test_curl_auth_emits_credential_on_success(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-4",
            capability=ToolCapability.CURL,
            metadata={
                "url": "http://target:8080/admin",
                "auth": "admin:secret123",
            },
        )

        self.assertEqual(len(bundle.tool_output.credentials), 1)
        cred = bundle.tool_output.credentials[0]
        self.assertEqual(cred.username, "admin")
        self.assertEqual(cred.credential_type, "http_basic")
        # Secret is masked in secret_ref
        self.assertIn("***", cred.secret_ref)
        self.assertNotIn("secret123", cred.secret_ref)

    def test_curl_session_state_delta_applies_to_run_state(self) -> None:
        from killchain_docker.tools.plugins.curl import build_output as curl_output_builder

        plane = ExecutionPlane()
        plugin = _StaticCurlPlugin()
        plane.register(plugin, curl_output_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-curl-5",
            capability=ToolCapability.CURL,
            metadata={"url": "http://target:8080/login", "session_id": "sess-1"},
        )

        state = RunState(objective="Solve web challenge.", authorized_scope=[])
        todo = state.queue_todo(TodoItem(goal="Login to target"))
        state.apply_worker_result(
            WorkerResult(
                todo_id=todo.todo_id,
                worker_name="web-worker",
                success=True,
                summary=bundle.parsed.summary,
                state_delta=bundle.state_delta,
                evidence_updates=[bundle.evidence],
            )
        )
        self.assertEqual(len(state.flag_candidates), 1)


class _StaticSqlmapPlugin:
    """Simulated sqlmap plugin returning canned injection results."""

    mode = ExecutionMode.SIMULATED
    name = "sqlmap"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                "[INFO] testing 'AND boolean-based blind'\n"
                "[INFO] GET parameter 'id' is vulnerable\n"
                "Parameter: id (GET)\n"
                "    Type: boolean-based blind\n"
                "    Type: UNION query\n"
                "sqlmap identified the following injection point(s):\n"
                "back-end DBMS: MySQL >= 5.0\n"
                "available databases [2]:\n"
                "[*] information_schema\n"
                "[*] ctf_db\n"
                "flag{sqli_found_1234}\n"
            ),
        )


class _StaticNiktoPlugin:
    """Simulated nikto plugin returning canned scan results."""

    mode = ExecutionMode.SIMULATED
    name = "nikto"

    def __init__(self) -> None:
        self.last_request: ToolExecutionRequest | None = None

    def execute(self, request: ToolExecutionRequest) -> ToolExecutionResult:
        self.last_request = request
        return ToolExecutionResult(
            tool_name=self.name,
            mode=self.mode,
            exit_code=0,
            stdout=(
                "+ Target IP: 10.0.0.1\n"
                "+ Server: Apache/2.4.41\n"
                "+ /admin/: Directory listing found.\n"
                "+ OSVDB-3092: /phpinfo.php: phpinfo() information disclosure\n"
                "+ /shell.php: Possible backdoor found (remote code execution)\n"
                "+ /login.php: Default credential page\n"
                "+ Start Time: 2026-05-17\n"
            ),
        )


class SqlmapSessionTests(unittest.TestCase):
    """Tests for sqlmap plugin with session support and richer output."""

    def test_sqlmap_detects_injection_and_emits_findings(self) -> None:
        from killchain_docker.tools.plugins.sqlmap import build_output as sqlmap_builder

        plane = ExecutionPlane()
        plugin = _StaticSqlmapPlugin()
        plane.register(plugin, sqlmap_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-sqlmap-1",
            capability=ToolCapability.SQLMAP,
            metadata={"url": "http://target:8080/page?id=1"},
        )

        self.assertEqual(bundle.tool_output.status.value, "success")
        self.assertIn("INJECTABLE", bundle.tool_output.summary)
        self.assertIn("MySQL", bundle.tool_output.summary)
        # Findings emitted
        self.assertTrue(len(bundle.tool_output.findings) >= 1)
        self.assertEqual(bundle.tool_output.findings[0].severity, "critical")
        # Vulnerabilities for each parameter
        self.assertTrue(len(bundle.tool_output.vulnerabilities) >= 1)
        self.assertIn("id", bundle.tool_output.vulnerabilities[0].title)
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        self.assertEqual(bundle.tool_output.endpoints[0].hostname, "target")
        # output_context has detailed info
        ctx = bundle.tool_output.output_context
        self.assertTrue(ctx["injectable"])
        self.assertEqual(ctx["dbms"], "MySQL >= 5.0")
        self.assertIn("id", ctx["vulnerable_params"])
        self.assertIn("ctf_db", ctx["databases"])
        # Flag extracted
        self.assertTrue(any(
            fc.value == "flag{sqli_found_1234}"
            for fc in bundle.tool_output.flag_candidates
        ))

    def test_sqlmap_session_id_in_summary(self) -> None:
        from killchain_docker.tools.plugins.sqlmap import build_output as sqlmap_builder

        plane = ExecutionPlane()
        plugin = _StaticSqlmapPlugin()
        plane.register(plugin, sqlmap_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-sqlmap-2",
            capability=ToolCapability.SQLMAP,
            metadata={"url": "http://target/page?id=1", "session_id": "auth-sess"},
        )

        self.assertIn("[session:auth-sess]", bundle.tool_output.summary)
        self.assertEqual(bundle.tool_output.output_context["session_id"], "auth-sess")


class NiktoSessionTests(unittest.TestCase):
    """Tests for nikto plugin with session support and richer output."""

    def test_nikto_parses_findings_with_severity(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-1",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080"},
        )

        self.assertEqual(bundle.tool_output.status.value, "success")
        # Vulnerabilities emitted with severity classification
        vulns = bundle.tool_output.vulnerabilities
        self.assertTrue(len(vulns) >= 3)
        # shell.php should be high severity (backdoor / RCE)
        shell_vulns = [v for v in vulns if "shell" in v.title.lower() or "backdoor" in v.title.lower()]
        self.assertTrue(len(shell_vulns) >= 1)
        self.assertEqual(shell_vulns[0].severity, "high")
        # phpinfo should be medium severity (information disclosure)
        phpinfo_vulns = [v for v in vulns if "phpinfo" in v.title.lower()]
        self.assertTrue(len(phpinfo_vulns) >= 1)
        self.assertEqual(phpinfo_vulns[0].severity, "medium")
        # Endpoint emitted
        self.assertEqual(len(bundle.tool_output.endpoints), 1)
        ep = bundle.tool_output.endpoints[0]
        self.assertEqual(ep.hostname, "target")
        self.assertTrue(ep.metadata.get("nikto_scanned"))
        # output_context has server info and severity counts
        ctx = bundle.tool_output.output_context
        self.assertEqual(ctx["server"], "Apache/2.4.41")
        self.assertEqual(ctx["target_ip"], "10.0.0.1")
        self.assertTrue(ctx["severity_counts"]["high"] >= 1)
        self.assertTrue(ctx["severity_counts"]["medium"] >= 1)

    def test_nikto_session_id_in_summary(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-2",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080", "session_id": "web-scan"},
        )

        self.assertIn("[session:web-scan]", bundle.tool_output.summary)
        self.assertEqual(bundle.tool_output.output_context["session_id"], "web-scan")

    def test_nikto_summary_includes_server(self) -> None:
        from killchain_docker.tools.plugins.nikto import build_output as nikto_builder

        plane = ExecutionPlane()
        plugin = _StaticNiktoPlugin()
        plane.register(plugin, nikto_builder)

        bundle = ToolGateway(plane).run(
            task_id="task-nikto-3",
            capability=ToolCapability.NIKTO,
            metadata={"target": "http://target:8080"},
        )

        self.assertIn("Apache/2.4.41", bundle.tool_output.summary)
        self.assertIn("finding(s)", bundle.tool_output.summary)


if __name__ == "__main__":
    unittest.main()
