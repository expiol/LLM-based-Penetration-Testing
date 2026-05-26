"""Dataset discovery for local RAG corpus loading."""

from __future__ import annotations

import os
from pathlib import Path

from killchain_docker.logging_utils import get_logger


LOGGER = get_logger(__name__)


def resolve_rag_dataset_paths(
    override: str | None = None,
) -> tuple[Path, Path] | None:
    """Return ``(dataset_root, split_index_json)`` or ``None`` when missing."""

    if override:
        root = Path(override).expanduser().resolve()
    else:
        env_root = (os.getenv("AUTOPENTEST_RAG_DATASET_ROOT") or "").strip()
        if env_root:
            root = Path(env_root).expanduser().resolve()
        else:
            try:
                from nyuctf.dataset import CTFDataset
            except Exception:
                LOGGER.debug(
                    "RAG dataset auto-discovery unavailable",
                    exc_info=True,
                    extra={"dataset_root_env": bool(env_root)},
                )
                return None
            try:
                ds = CTFDataset(split="development")
            except Exception:
                LOGGER.debug(
                    "RAG dataset auto-discovery failed",
                    exc_info=True,
                    extra={"split": "development"},
                )
                return None
            root = Path(ds.basedir)

    if not root.is_dir():
        return None
    candidate = root / "development_dataset.json"
    if not candidate.is_file():
        return None
    return root, candidate
