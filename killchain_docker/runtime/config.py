"""Runtime configuration and artifact descriptors."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class RunConfig(BaseModel):
    """Configuration for one local assessment run."""

    model_config = ConfigDict(extra="ignore")

    objective: str
    authorized_scope: list[str]
    output_root: str = "runs"
    max_cycles: int = Field(default=8, ge=1)
    quiet: bool = False
    status_path: str | None = None
    rag_mode: str | None = None
    memory_root: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "RunConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.model_validate(payload)


class RunArtifacts(BaseModel):
    """Filesystem outputs produced by a run."""

    run_id: str
    run_dir: str
    state_path: str
    summary_path: str
    report_path: str
    events_path: str
    config_path: str
    evidence_path: str
    compact_json_path: str
    compact_markdown_path: str
    status: str
