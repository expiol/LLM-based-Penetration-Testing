"""Helpers for distinguishing challenge result logs from batch metadata."""

from __future__ import annotations

from pathlib import Path


BATCH_ARTIFACT_JSON_NAMES = frozenset(
    {
        "_batch_monitor.json",
        "_batch_summary.json",
        "_rag_ablation.json",
        "_rag_ablation_audit.json",
    }
)


def is_result_log_path(path: Path) -> bool:
    """Return true for per-challenge JSON logs in a batch log directory."""

    return (
        path.suffix == ".json"
        and path.name not in BATCH_ARTIFACT_JSON_NAMES
        and not path.name.endswith(".status.json")
    )


def iter_result_logs(logdir: Path) -> list[Path]:
    """Return sorted per-challenge JSON logs from *logdir*."""

    return sorted(path for path in logdir.glob("*.json") if is_result_log_path(path))
