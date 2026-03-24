"""Small runtime compatibility shims."""

from __future__ import annotations

try:
    from enum import StrEnum
except ImportError:  # Python < 3.11
    from enum import Enum

    class StrEnum(str, Enum):
        """Subset of ``enum.StrEnum`` behavior for older interpreters."""
