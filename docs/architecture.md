# Architecture

AutoPentest is a research platform for orchestrating multi-agent security assessment workflows. The system is organized around:

- A LangGraph state machine that coordinates agents.
- A plugin-based tool execution layer.
- Evidence and artifact storage to ensure traceability.
- Structured events for observability and evaluation.

## Core components

- `graph/workflow.py`: LangGraph state machine and transitions.
- `agents/*`: recon, analysis, planning, validation, reporting agents.
- `tools/registry.py` and `tools/runner.py`: tool registration and execution.
- `memory/evidence_store.py`: evidence and artifact persistence.
- `orchestrator/controller.py`: run lifecycle coordination.
- `evaluation/*`: benchmark execution and metrics reporting.

## Data flow

1. CLI validates scope and loads target config.
2. Orchestrator builds run context and LangGraph workflow.
3. Recon agent executes network and HTTP probes.
4. Analysis agent generates initial findings from recon artifacts.
5. Planning agent builds a validation plan.
6. Validation agent executes safe checks and records evidence.
7. Reporting agent generates Markdown report.

All outputs are written under `runs/<run_id>/` for reproducibility.
