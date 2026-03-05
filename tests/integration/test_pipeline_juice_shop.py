from pathlib import Path
from shutil import which

import httpx
import pytest

from autopentest.orchestrator.controller import run_assessment
from autopentest.utils.serialization import read_json


def _lab_ready(url: str) -> bool:
    try:
        response = httpx.get(url, timeout=3)
        return response.status_code < 500
    except httpx.RequestError:
        return False


def test_pipeline_juice_shop() -> None:
    if which("nmap") is None:
        pytest.skip("nmap not installed; run in lab container")
    if not _lab_ready("http://127.0.0.1:3000"):
        pytest.skip("Juice Shop not reachable; run scripts/lab_up.sh")

    result = run_assessment(
        target_path=Path("data/targets/juice_shop_local.yaml"),
        config_path=Path("configs/dev.yaml"),
        authorized=True,
        success_strategy="juice_shop",
    )

    run_dir = result.run_dir
    summary = read_json(run_dir / "summary.json")
    assert summary["success"] is True

    expected_files = [
        run_dir / "config_resolved.yaml",
        run_dir / "events.jsonl",
        run_dir / "summary.json",
        run_dir / "report.md",
        run_dir / "artifacts" / "recon.json",
        run_dir / "artifacts" / "validation_plan.json",
        run_dir / "artifacts" / "session.json",
    ]
    for path in expected_files:
        assert path.exists()
