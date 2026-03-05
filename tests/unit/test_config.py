from pathlib import Path

from autopentest.core.config import load_config


def test_load_config() -> None:
    config = load_config(Path("configs/default.yaml"))
    assert config.runs_root == "runs"
    assert config.budget.max_steps > 0
