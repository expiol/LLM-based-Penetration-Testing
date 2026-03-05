import pytest

from autopentest.schemas.messages import Target


def test_target_schema_requires_fields() -> None:
    with pytest.raises(Exception):
        Target.model_validate({"target_id": "x"})
