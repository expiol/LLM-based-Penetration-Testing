# Experiment Design

AutoPentest runs are designed to be reproducible and measurable.

## Reproducibility

- Each run stores `config_resolved.yaml` and `target.yaml` in `runs/<run_id>/`.
- Evidence and artifacts are stored under `runs/<run_id>/evidence` and `runs/<run_id>/artifacts`.

## Evaluation

Benchmarks execute multiple tasks and produce:

- `metrics.csv`
- `metrics.json`
- `report.md`

Metrics include success, runtime_s, steps, and tool_calls.

## Observability

- Structured events are written to `events.jsonl`.
- Logs are emitted to console and `runs/<run_id>/logs.jsonl`.
