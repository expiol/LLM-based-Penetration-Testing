"""Runnable entry point for a local assessment run.

Loads scope and objective from configs/sample_run.json when present.
For production, use RunConfig.from_json_file() with your own config path.
"""

from __future__ import annotations

import json
from pathlib import Path

from nyuctf_mutil_killchain.controller import RunConfig, run_assessment


def main() -> None:
    """Run a single assessment. Config from configs/sample_run.json or inline defaults."""
    config_path = Path.cwd() / "configs" / "sample_run.json"
    if config_path.exists():
        config = RunConfig.from_json_file(config_path)
    else:
        config = RunConfig(
            objective="Map and review authorized web surface",
            authorized_scope=["http://127.0.0.1:8080"],
            output_root="runs",
            max_cycles=4,
            quiet=False,
        )
    artifacts = run_assessment(config)
    print(
        json.dumps(
            {
            "run_id": artifacts.run_id,
            "status": artifacts.status,
            "run_dir": artifacts.run_dir,
            "report_path": artifacts.report_path,
            },
            indent=2,
            ensure_ascii=True,
        )
    )


if __name__ == "__main__":
    main()
