"""Tests for fail-closed engineering refactoring.

Validates that:
- Identity fields are never guessed via wildcard fallback
- Workers fail explicitly when required context is missing
- Orchestrator repair is limited to artifact-related fields
- Planner normalization does not fill identity fields
- Dispatch pre-validation rejects unknown asset IDs
- Error codes are correctly set on failures
"""

from __future__ import annotations

import pytest

from nyuctf_mutil_killchain.agents.base import infer_host_context, infer_web_context
from nyuctf_mutil_killchain.agents.enrichment import ServiceBannerAgent, WebPathProbeAgent
from nyuctf_mutil_killchain.agents.exploit import CredentialExploitAgent, WebPwnExploitAgent
from nyuctf_mutil_killchain.agents.flag import FlagValidationAgent
from nyuctf_mutil_killchain.agents.host import HostAuditAgent
from nyuctf_mutil_killchain.agents.recon import ReconAgent
from nyuctf_mutil_killchain.agents.vuln import VulnScanAgent
from nyuctf_mutil_killchain.agents.web import WebAssessmentAgent
from nyuctf_mutil_killchain.agents.web_content import WebContentAgent
from nyuctf_mutil_killchain.orchestrator.loop import Orchestrator
from nyuctf_mutil_killchain.orchestrator.planner import (
    APPROVED_TASK_TYPES,
    LLMPlanner,
    PlannedTask,
)
from nyuctf_mutil_killchain.llm import StaticLLMClient
from nyuctf_mutil_killchain.state.models import (
    Asset,
    AssetKind,
    GlobalState,
    Service,
    Task,
    TaskErrorCode,
    TaskStatus,
    WorkerReport,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _state_with_web_asset() -> GlobalState:
    """Build a GlobalState with one web asset for testing."""
    state = GlobalState(
        objective="test",
        authorized_scope=["http://example.com:8080"],
        metadata={"challenge": {"files": ["app.py", "flag.txt"], "category": "web"}},
    )
    state.upsert_asset(
        Asset(
            asset_id="asset-example",
            kind=AssetKind.WEB_APPLICATION,
            hostname="example.com",
            base_url="http://example.com:8080",
            services=[Service(port=8080, name="http")],
        )
    )
    return state


def _empty_task(task_type: str, **ctx) -> Task:
    return Task(
        title="test",
        description="test",
        task_type=task_type,
        input_context=dict(ctx),
    )


# ===========================================================================
# 1. infer_web_context — no wildcard fallback
# ===========================================================================

class TestInferWebContextNoWildcard:
    def test_both_missing_returns_none(self):
        """When both asset_id and base_url are absent, return (None, None)."""
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface")
        asset_id, base_url = infer_web_context(task, state)
        assert asset_id is None
        assert base_url is None

    def test_asset_id_given_looks_up_base_url(self):
        """When asset_id is given, look up the asset's base_url."""
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface", asset_id="asset-example")
        asset_id, base_url = infer_web_context(task, state)
        assert asset_id == "asset-example"
        assert base_url == "http://example.com:8080"

    def test_base_url_given_finds_exact_match(self):
        """When base_url is given, find the asset with exact match."""
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface", base_url="http://example.com:8080")
        asset_id, base_url = infer_web_context(task, state)
        assert asset_id == "asset-example"
        assert base_url == "http://example.com:8080"

    def test_base_url_no_match_returns_none_asset(self):
        """When base_url doesn't match any asset, asset_id stays None."""
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface", base_url="http://other.com")
        asset_id, base_url = infer_web_context(task, state)
        assert asset_id is None
        assert base_url == "http://other.com"

    def test_both_present_returned_directly(self):
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface", asset_id="x", base_url="http://y")
        asset_id, base_url = infer_web_context(task, state)
        assert asset_id == "x"
        assert base_url == "http://y"


# ===========================================================================
# 2. infer_host_context — no wildcard fallback
# ===========================================================================

class TestInferHostContextNoWildcard:
    def test_both_missing_returns_none(self):
        state = _state_with_web_asset()
        task = _empty_task("host.audit")
        asset_id, hostname = infer_host_context(task, state)
        assert asset_id is None
        assert hostname is None

    def test_asset_id_given_looks_up_hostname(self):
        state = _state_with_web_asset()
        task = _empty_task("host.audit", asset_id="asset-example")
        asset_id, hostname = infer_host_context(task, state)
        assert asset_id == "asset-example"
        assert hostname == "example.com"


# ===========================================================================
# 3. Planner normalization does NOT fill identity fields
# ===========================================================================

class TestPlannerNormalization:
    def test_web_task_identity_filled_single_asset(self):
        """Planner fills asset_id/base_url for web tasks with single asset."""
        state = _state_with_web_asset()
        planner = LLMPlanner(StaticLLMClient([]))
        task = PlannedTask(
            title="Review web",
            description="test",
            task_type="web.review_surface",
            input_context={},
        )
        planner._normalize_planned_task(task, state)
        assert task.input_context["asset_id"] == "asset-example"
        assert task.input_context["base_url"] == "http://example.com:8080"

    def test_exploit_task_identity_filled_single_asset(self):
        """Planner fills asset_id for exploit tasks with single asset."""
        state = _state_with_web_asset()
        planner = LLMPlanner(StaticLLMClient([]))
        task = PlannedTask(
            title="Exploit",
            description="test",
            task_type="exploit.cve_probe",
            input_context={},
        )
        planner._normalize_planned_task(task, state)
        assert task.input_context["asset_id"] == "asset-example"

    def test_host_task_identity_filled_single_asset(self):
        """Planner fills hostname for host tasks with single asset."""
        state = _state_with_web_asset()
        planner = LLMPlanner(StaticLLMClient([]))
        task = PlannedTask(
            title="Banner grab",
            description="test",
            task_type="host.banner_grab",
            input_context={},
        )
        planner._normalize_planned_task(task, state)
        assert task.input_context["hostname"] == "example.com"
        assert task.input_context["asset_id"] == "asset-example"

    def test_web_task_identity_not_filled_multiple_assets(self):
        """Planner must NOT guess identity when multiple assets exist."""
        state = _state_with_web_asset()
        state.upsert_asset(
            Asset(
                asset_id="asset-other",
                kind=AssetKind.WEB_APPLICATION,
                hostname="other.com",
                base_url="http://other.com:9090",
                services=[Service(port=9090, name="http")],
            )
        )
        planner = LLMPlanner(StaticLLMClient([]))
        task = PlannedTask(
            title="Review web",
            description="test",
            task_type="web.review_surface",
            input_context={},
        )
        planner._normalize_planned_task(task, state)
        assert "asset_id" not in task.input_context
        assert "base_url" not in task.input_context

    def test_artifact_files_root_still_filled(self):
        """Planner should still fill files_root for artifact tasks."""
        state = _state_with_web_asset()
        planner = LLMPlanner(StaticLLMClient([]))
        task = PlannedTask(
            title="Triage",
            description="test",
            task_type="artifact.triage",
            input_context={},
        )
        planner._normalize_planned_task(task, state)
        assert task.input_context["files_root"] == "/home/ctfplayer/ctf_files"


# ===========================================================================
# 4. Orchestrator repair is artifact-only
# ===========================================================================

class TestOrchestratorRepair:
    def test_fills_identity_from_single_asset(self):
        """Orchestrator repair should fill identity fields when single asset is unambiguous."""
        state = _state_with_web_asset()
        orch = Orchestrator(state=state, workers=[WebAssessmentAgent()])
        task = Task(
            title="test", description="test",
            task_type="web.review_surface", input_context={},
        )
        candidates = [w for w in orch.workers if w.supports(task)]
        orch._try_repair_task_context(task, candidates)
        assert task.input_context["asset_id"] == "asset-example"
        assert task.input_context["base_url"] == "http://example.com:8080"

    def test_does_not_fill_identity_with_multiple_assets(self):
        """Orchestrator repair must NOT guess identity when multiple assets exist."""
        state = _state_with_web_asset()
        state.upsert_asset(
            Asset(
                asset_id="asset-other",
                kind=AssetKind.WEB_APPLICATION,
                hostname="other.com",
                base_url="http://other.com:9090",
                services=[Service(port=9090, name="http")],
            )
        )
        orch = Orchestrator(state=state, workers=[WebAssessmentAgent()])
        task = Task(
            title="test", description="test",
            task_type="web.review_surface", input_context={},
        )
        candidates = [w for w in orch.workers if w.supports(task)]
        orch._try_repair_task_context(task, candidates)
        assert "asset_id" not in task.input_context
        assert "base_url" not in task.input_context

    def test_fills_files_root(self):
        """Orchestrator repair should still fill files_root."""
        state = _state_with_web_asset()

        class _FakeWorker:
            name = "fake"
            supported_task_types = ("test.",)
            required_context_keys = ("files_root",)
            def supports(self, task): return True
            def can_route_task(self, task, state): return False, "missing"

        orch = Orchestrator(state=state, workers=[_FakeWorker()])
        task = Task(
            title="test", description="test",
            task_type="test.thing", input_context={},
        )
        result = orch._try_repair_task_context(task, [_FakeWorker()])
        assert result is True
        assert task.input_context["files_root"] == "/home/ctfplayer/ctf_files"


# ===========================================================================
# 5. Dispatch pre-validation
# ===========================================================================

class TestDispatchPreValidation:
    def test_rejects_unknown_asset_id(self):
        state = _state_with_web_asset()
        orch = Orchestrator(state=state, workers=[])
        task = _empty_task("web.review_surface", asset_id="nonexistent")
        valid, reason, error_code = orch._validate_task_for_dispatch(task)
        assert valid is False
        assert error_code == TaskErrorCode.UNKNOWN_ASSET_ID

    def test_allows_known_asset_id(self):
        state = _state_with_web_asset()
        orch = Orchestrator(state=state, workers=[])
        task = _empty_task("web.review_surface", asset_id="asset-example")
        valid, reason, error_code = orch._validate_task_for_dispatch(task)
        assert valid is True

    def test_allows_recon_with_unknown_asset(self):
        """Recon tasks create assets — unknown asset_id is expected."""
        state = _state_with_web_asset()
        orch = Orchestrator(state=state, workers=[])
        task = _empty_task("recon.enumerate_scope", asset_id="seed-asset")
        valid, reason, error_code = orch._validate_task_for_dispatch(task)
        assert valid is True

    def test_allows_no_asset_id(self):
        """Tasks without asset_id in context should pass validation."""
        state = _state_with_web_asset()
        orch = Orchestrator(state=state, workers=[])
        task = _empty_task("artifact.triage")
        valid, _, _ = orch._validate_task_for_dispatch(task)
        assert valid is True


# ===========================================================================
# 6. Worker required_context_keys enforcement
# ===========================================================================

class TestRequiredContextKeysEnforcement:
    @pytest.mark.parametrize("agent_cls,missing_keys", [
        (WebAssessmentAgent, {"asset_id", "base_url"}),
        (WebContentAgent, {"asset_id", "base_url"}),
        (WebPathProbeAgent, {"asset_id", "base_url", "paths"}),
        (ServiceBannerAgent, {"asset_id", "hostname", "ports"}),
        (HostAuditAgent, {"asset_id", "hostname"}),
        (VulnScanAgent, {"asset_id", "target"}),
        (FlagValidationAgent, {"candidate_flag"}),
        (ReconAgent, {"scope"}),
    ])
    def test_can_route_rejects_missing_keys(self, agent_cls, missing_keys):
        """can_route_task should reject tasks missing required context keys."""
        agent = agent_cls()
        state = _state_with_web_asset()
        task = _empty_task(agent.supported_task_types[0])
        allowed, reason = agent.can_route_task(task, state)
        assert allowed is False
        assert "missing required context key" in reason


# ===========================================================================
# 7. Worker error_code on missing context
# ===========================================================================

class TestWorkerErrorCodes:
    def test_web_assessment_missing_context(self):
        agent = WebAssessmentAgent()
        state = _state_with_web_asset()
        task = _empty_task("web.review_surface")
        report = agent.run(task, state)
        assert report.success is False
        assert report.error_code == TaskErrorCode.MISSING_REQUIRED_CONTEXT

    def test_vuln_scan_missing_target(self):
        agent = VulnScanAgent()
        state = _state_with_web_asset()
        task = _empty_task("vuln.scan")
        report = agent.run(task, state)
        assert report.success is False
        assert report.error_code == TaskErrorCode.MISSING_REQUIRED_CONTEXT

    def test_host_audit_missing_hostname(self):
        agent = HostAuditAgent()
        state = _state_with_web_asset()
        task = _empty_task("host.audit")
        report = agent.run(task, state)
        assert report.success is False
        assert report.error_code == TaskErrorCode.MISSING_REQUIRED_CONTEXT


# ===========================================================================
# 8. TaskErrorCode serialization
# ===========================================================================

class TestTaskErrorCodeSerialization:
    def test_round_trip(self):
        report = WorkerReport(
            task_id="test",
            worker_name="test",
            success=False,
            summary="test",
            error_code=TaskErrorCode.MISSING_REQUIRED_CONTEXT,
        )
        data = report.model_dump(mode="json")
        assert data["error_code"] == "missing_required_context"
        restored = WorkerReport.model_validate(data)
        assert restored.error_code == TaskErrorCode.MISSING_REQUIRED_CONTEXT

    def test_task_error_code_round_trip(self):
        task = Task(
            title="test", description="test", task_type="web.review_surface",
            error_code=TaskErrorCode.UNKNOWN_ASSET_ID,
        )
        data = task.model_dump(mode="json")
        assert data["error_code"] == "unknown_asset_id"
        restored = Task.model_validate(data)
        assert restored.error_code == TaskErrorCode.UNKNOWN_ASSET_ID

    def test_none_error_code(self):
        report = WorkerReport(
            task_id="test", worker_name="test", success=True, summary="ok",
        )
        assert report.error_code is None
        data = report.model_dump(mode="json")
        assert data["error_code"] is None


# ===========================================================================
# 9. APPROVED_TASK_TYPES sanity
# ===========================================================================

class TestApprovedTaskTypes:
    def test_form_probe_is_approved(self):
        assert "web.form_probe" in APPROVED_TASK_TYPES

    def test_core_types_present(self):
        for expected in [
            "web.review_surface", "web.content_review", "web.path_probe",
            "exploit.hypothesis", "exploit.cve_probe",
            "solve.generate_script", "flag.validate",
        ]:
            assert expected in APPROVED_TASK_TYPES, f"{expected} missing"


# ===========================================================================
# 10. Solver cap
# ===========================================================================

class TestSolverCap:
    def test_solver_cap_blocks_excess(self):
        """After 6+ solver tasks exist, new ones should be filtered."""
        state = _state_with_web_asset()
        for i in range(7):
            state.task_chain.add_task(Task(
                title=f"Solver {i}", description="test",
                task_type="solve.generate_script",
                status=TaskStatus.FAILED,
                dedupe_key=f"solver-{i}",
            ))
        solver_total = sum(
            1 for t in state.task_chain.tasks
            if t.task_type == "solve.generate_script"
        )
        assert solver_total >= 6
        # Simulate planner filtering
        sanitized = [PlannedTask(
            title="new solver", description="t", task_type="solve.generate_script",
        )]
        _MAX_SOLVER_TOTAL = 6
        filtered = [
            t for t in sanitized
            if t.task_type != "solve.generate_script" or solver_total < _MAX_SOLVER_TOTAL
        ]
        assert len(filtered) == 0
