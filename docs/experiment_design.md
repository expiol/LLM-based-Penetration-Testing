# Experiment Design

AutoPentest runs are designed to be reproducible and measurable.

## Reproducibility

- Each run stores `config.yaml`, `target.yaml`, and `scope.yaml` under `runs/<run_id>/`.
- Evidence and artifacts are stored with deterministic naming and timestamps.

## Evaluation

Benchmark runs execute multiple tasks from a benchmark file and produce:

- `metrics.csv`
- `metrics.json`
- `report.md`

Metrics include success, runtime, steps, and tool calls.

## Observability

- Structured events are written to `events.jsonl`.
- Logs are emitted to console and `runs/<run_id>/logs.jsonl`.
