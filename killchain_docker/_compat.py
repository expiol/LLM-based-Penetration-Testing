"""Python 3.10 compatibility shim for StrEnum (added in 3.11)."""

from __future__ import annotations

import sys

if sys.version_info >= (3, 11):
    from enum import StrEnum
else:
    from enum import Enum

    class StrEnum(str, Enum):
        """Minimal StrEnum backport for Python 3.10."""

        def __new__(cls, value: str) -> "StrEnum":
            obj = str.__new__(cls, value)
            obj._value_ = value
            return obj

        def __str__(self) -> str:
            return self.value


__all__ = ["StrEnum"]
