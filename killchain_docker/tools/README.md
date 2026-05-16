# Tools Package

`killchain_docker.tools` is organized around a small execution framework plus one module per tool.

## Layout

- `core.py`: shared execution-plane types, safe command/REST adapters, evidence bundling
- `capabilities.py`: stable `ToolCapability` enum and the `ToolGateway` adapter
- `parsers.py`: JSONL and JSON payload parsers
- `registry.py`: `build_execution_plane()` and default plugin registration
- `plugins/`: one Python module per concrete tool

## Plugin Convention

Each file under `plugins/` should expose:

- `TOOL_NAME`
- `SCRIPT` (an inline Python program executed inside the agent container, when the plugin uses `AllowlistedCommandPlugin`)
- `build_arguments(request)` returning the argv suffix passed to the executable
- `build_tool_output(request, result, parsed)` returning `ToolOutput`

Each plugin owns its own output shaping, typed signal extraction, and
`output_context` structure. The execution plane requires `build_tool_output()`
and does not infer state updates from plugin-specific fields.

## Current Plugins

- `archive_triage.py`
- `artifact_triage.py`
- `binary_disassembly.py`
- `binary_run.py`
- `binary_triage.py`
- `computation_analysis.py`
- `credential_harvest.py`
- `credential_login_probe.py`
- `ctf_exploit_probe.py`
- `flag_harvest.py`
- `host_inventory.py`
- `http_content.py`
- `http_form_probe.py`
- `http_metadata.py`
- `http_path_probe.py`
- `pcap_review.py`
- `repo_review.py`
- `runtime_probe.py`
- `script_execution.py`
- `source_review.py`
- `sqlite_review.py`
- `tcp_banner_probe.py`
- `vuln_scan.py`
