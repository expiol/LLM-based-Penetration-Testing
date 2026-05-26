"""Challenge metadata projection over durable run state."""

from __future__ import annotations

import re
from typing import Any, TYPE_CHECKING

from killchain_docker.state.metadata import RunMetadataStore

if TYPE_CHECKING:
    from killchain_docker.state.run_state import RunState

_PREFIX_FROM_FORMAT_RE = re.compile("^([A-Za-z0-9_]+)(?:\\\\?\\{|\\{)")


class ChallengeProjection:
    """Read-only challenge metadata used by planners, runtime, and workers."""

    def __init__(self, state: "RunState") -> None:
        self.metadata = RunMetadataStore(state)

    def category(self) -> str:
        return str(self.metadata.challenge().get("category") or "misc").lower()

    def category_raw(self) -> str:
        return str(self.metadata.challenge().get("category") or "").strip().lower()

    def payload(self) -> dict[str, Any]:
        challenge = self.metadata.challenge()
        return {
            "canonical_name": challenge.get("canonical_name"),
            "name": challenge.get("name"),
            "category": challenge.get("category"),
            "flag_format": challenge.get("flag_format"),
            "files": challenge.get("files") or [],
            "server_name": challenge.get("server_name"),
            "port": challenge.get("port"),
        }

    def flag_format(self) -> object:
        return self.metadata.challenge().get("flag_format")

    def flag_format_prefix(self) -> str | None:
        raw = str(self.flag_format() or "").strip()
        if not raw:
            return None
        match = _PREFIX_FROM_FORMAT_RE.match(raw)
        if not match:
            return None
        return match.group(1)

    def files(self) -> list[object]:
        files = self.metadata.challenge().get("files") or []
        return list(files) if isinstance(files, list) else []

    def name(self) -> str | None:
        return self.metadata.challenge_name()
