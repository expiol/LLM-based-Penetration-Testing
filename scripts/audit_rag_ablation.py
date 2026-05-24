"""CLI wrapper for RAG ablation artifact audits."""

from __future__ import annotations

from _bootstrap import add_project_root


add_project_root()

from killchain_docker.batch.audit import main


if __name__ == "__main__":
    raise SystemExit(main())
