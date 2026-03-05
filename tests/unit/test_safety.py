from pathlib import Path

import pytest

from autopentest.core.config import load_config
from autopentest.core.safety import CommandSafetyError, ScopeViolationError, validate_authorization
from autopentest.schemas.messages import Target


def test_authorization_requires_flag() -> None:
    config = load_config(Path("configs/default.yaml"))
    target = Target(
        target_id="t1",
        scope="local_lab",
        host="127.0.0.1",
        base_url="http://127.0.0.1:8080",
        allowed_tools=["nmap"],
        ports=[8080],
    )
    with pytest.raises(ScopeViolationError):
        validate_authorization(target, config, authorized=False)


def test_authorization_rejects_scope() -> None:
    config = load_config(Path("configs/default.yaml"))
    target = Target(
        target_id="t1",
        scope="other",
        host="127.0.0.1",
        base_url="http://127.0.0.1:8080",
        allowed_tools=["nmap"],
        ports=[8080],
    )
    with pytest.raises(ScopeViolationError):
        validate_authorization(target, config, authorized=True)
