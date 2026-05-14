# Tools Package

`killchain_docker.tools` is organized around a small execution framework plus one module per tool.

## Layout

- `core.py`: shared execution-plane types, safe command/REST adapters, evidence bundling
- `parsers.py`: JSONL and JSON payload parsers
- `registry.py`: `build_execution_plane()` and default plugin registration
- `plugins/`: one Python module per concrete tool

## Plugin Convention

Each file under `plugins/` should expose:

- `TOOL_NAME`
- `SCRIPT`
- `build_arguments(request)`

This keeps registration uniform and makes each tool independently testable.

## Current Plugins

- `artifact_triage.py`
- `archive_triage.py`
- `binary_triage.py`
- `host_inventory.py`
- `http_content.py`
- `http_metadata.py`
- `http_path_probe.py`
- `pcap_review.py`
- `repo_review.py`
- `source_review.py`
- `sqlite_review.py`
- `tcp_banner_probe.py`
- `vuln_scan.py`
