import pytest

from autopentest.core.safety import ScopeViolationError, validate_scope
from autopentest.schemas.messages import Scope, Target


def test_scope_allows_host() -> None:
    target = Target(name="local", hosts=["127.0.0.1"], ports=[], urls=[])
    scope = Scope(name="local", allowed_hosts=[], allowed_networks=["127.0.0.0/8"], allowed_urls=[])
    validate_scope(target, scope)


def test_scope_blocks_host() -> None:
    target = Target(name="private", hosts=["10.0.0.1"], ports=[], urls=[])
    scope = Scope(name="local", allowed_hosts=[], allowed_networks=["127.0.0.0/8"], allowed_urls=[])
    with pytest.raises(ScopeViolationError):
        validate_scope(target, scope)
