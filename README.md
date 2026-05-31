# LLM-based Penetration Testing

An LLM-driven autonomous CTF solving and authorized security assessment
framework. The project uses the NYUCTF dataset as its main benchmark and
combines LLM planning, task routing, persona-based workers, guarded tool
execution, Docker isolation, durable cross-run memory with optional networked
intelligence retrieval, batch evaluation, and run reporting into one
reproducible workflow.

> This project is intended for academic research, CTFs, security education, and
> explicitly authorized lab environments only. Do not use it against systems you
> do not own or have permission to test.

## Overview

Manual penetration testing and CTF solving require repeatedly switching between
reconnaissance, hypothesis generation, tool execution, exploit attempts, and
result validation. This project models that workflow as an observable kill chain.

At runtime, a Planner proposes high-level todos, a Router assigns them to
specialized workers, workers select concrete tool capabilities, and tool plugins
execute bounded commands inside the authorized environment. Each cycle updates a
shared run state and writes structured artifacts for debugging, scoring, and
post-run analysis.

The current implementation supports:

- Single challenge, category, subset, sampled, and full-split NYUCTF runs.
- Common CTF categories such as web, crypto, reverse, pwn, forensics, and misc.
- An OpenAI-compatible LLM gateway with Pydantic-validated structured output.
- Docker-based execution for tools such as nmap, curl, sqlmap, nikto, radare2,
  gdb, binwalk, tshark, steghide, john, and more.
- A multi-layer file-backed memory system (global and category scope) plus
  optional networked retrieval (CVE / MITRE ATT&CK / Exploit-DB) gated by an
  explicit knowledge mode, with challenge identifiers and the validated flag
  redacted from every outbound query.
- Runtime logs, live status files, static HTML batch monitoring, compact run
  timelines, Markdown reports, and experiment summaries.

## Architecture

```text
User / batch runner
        |
        v
+-------------------+       +-------------------+
| Runtime Session   | ----> | RunState / Memory |
+-------------------+       +-------------------+
        |
        v
+-------------------+       +-------------------+
| Planner Agent     | ----> | TodoQueue         |
+-------------------+       +-------------------+
        |
        v
+-------------------+
| Router Agent      |
+-------------------+
        |
        v
+-------------------------------------------------------+
| Persona Workers                                       |
| recon / artifact / web / exploit / flag               |
+-------------------------------------------------------+
        |
        v
+-------------------------------------------------------+
| Tool Plugins                                          |
| shell, script, nmap, curl, sqlmap, gdb, r2, tshark... |
+-------------------------------------------------------+
        |
        v
+-------------------+
| Docker lab/files  |
+-------------------+
```

One assessment loop works like this:

1. The Planner observes the objective, authorized scope, accumulated evidence,
   recalled durable memory, optional networked intelligence hits, and current
   run state.
2. It creates high-level todos only when more work is needed.
3. The Router assigns ready todos to the most suitable persona worker.
4. The worker asks the LLM for a concrete capability and metadata.
5. The selected tool plugin executes in a guarded local or Docker context.
6. Parsed output is merged back into evidence, assets, candidates, todos, and
   run metrics.
7. The state is persisted and the next cycle begins until the run is solved,
   exhausted, interrupted, or rejected by safety/configuration checks.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `run.py` | NYUCTF benchmark entrypoint for single, category, subset, random, and full runs |
| `killchain_docker/cli.py` | `autopentest` CLI for custom assessments, demos, self-test, and lab helpers |
| `killchain_docker/runtime/` | Runtime assembly, session execution, event recording, and artifact persistence |
| `killchain_docker/orchestrator/` | Planner, router, dispatch loop, progress policy, todo queue, and termination logic |
| `killchain_docker/workers/` | Persona workers, prompts, capability selection, correction, and result handling |
| `killchain_docker/tools/` | Tool abstractions, plugin registry, guard policies, and output parsers |
| `killchain_docker/state/` | RunState, evidence, artifacts, candidates, todos, report projections, and facts |
| `killchain_docker/llm/` | OpenAI-compatible gateway, JSON repair, typed failures, and token accounting |
| `killchain_docker/intelligence/` | Knowledge augmenter, durable-memory recall, and networked retrieval (CVE / ATT&CK / Exploit-DB) |
| `killchain_docker/memory/` | Filesystem-backed durable cross-run memory (global and category scope only) |
| `killchain_docker/batch/` | Dataset loading, Docker challenge lifecycle, parallel execution, and monitoring |
| `scripts/` | Analysis utilities for summaries, transcripts, flags, and plots |
| `tests/` | Unit tests and architecture contract tests |

## Persona Workers

| Worker | Responsibility |
| --- | --- |
| `recon-worker` | Scope mapping, port scanning, first-pass HTTP recon, file identification |
| `artifact-worker` | Offline analysis for files, binaries, pcaps, images, Office docs, archives, databases, and APKs |
| `web-worker` | HTTP probing, path exploration, vulnerability scanning, SQL injection checks |
| `exploit-worker` | Evidence-driven exploit attempts, credential attacks, binary debugging, active validation |
| `flag-worker` | Concrete flag candidate validation and final answer checking |

## Tool Capabilities

Tool plugins are registered in `killchain_docker/tools/registry.py`.

- General execution: `shell.exec`, `script.exec`
- Network and web: `nmap`, `curl`, `nikto`, `sqlmap`
- Binary and reversing: `file`, `strings`, `checksec`, `radare2`, `objdump`,
  `gdb`, `ltrace`, `strace`
- Forensics and steganography: `binwalk`, `tshark`, `exiftool`, `steghide`,
  `foremost`, `png.inspect`, `media.scan`, `office.inspect`, `disk.extract`
- Data and credentials: `sqlite3`, `john`, `fcrackzip`
- Mobile: `jadx`

The execution layer includes guardrails such as blocking package installation
inside `shell.exec`, preventing out-of-scope target access, discouraging
unbounded extraction, preserving stderr diagnostics, and pushing complex
multi-line code into `script.exec`.

## Requirements

- Python 3.11 or newer
- Conda
- Docker
- An OpenAI-compatible LLM API endpoint
- Optional: a local NYUCTF dataset cache, or the default dataset access provided
  by the `nyuctf` package

## Installation

Create and activate the Conda environment:

```bash
conda create -n autopentest python=3.11 -y
conda activate autopentest
```

Install Python dependencies:

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
```

Build the Docker execution environment:

```bash
bash setup.sh
```

`setup.sh` creates the Docker network, builds the `ctfenv:latest` image, and
installs this package into the `autopentest` Conda environment in editable mode.

## LLM Configuration

The gateway reads local credentials from:

```text
configs/llm_gateway.json
```

Create it from the public template:

```bash
cp configs/llm_gateway.example.json configs/llm_gateway.json
```

Example:

```json
{
  "provider": "openai_compatible",
  "base_url": "https://api.openai.com/v1",
  "api_key": "YOUR_API_KEY",
  "default_model": "gpt-4o",
  "schema_models": {
    "*": "gpt-4o"
  },
  "timeout_s": 180,
  "max_retries": 5,
  "total_deadline_s": 300,
  "max_completion_tokens": 65536
}
```

The gateway works with OpenAI, DeepSeek, Groq, Together, OpenRouter, or any
provider that exposes an OpenAI-compatible Chat Completions API. `schema_models`
can route specific structured-output schemas to different models; `"*"` is the
fallback override.

Do not commit real API keys. If a key has already been committed or shared,
rotate it before publishing the project.

## Quick Self-Test

Run a local deterministic self-test without a real Docker challenge or live LLM:

```bash
conda run -n autopentest autopentest selftest --output-root selftest_output
```

The self-test uses `StaticLLMClient` and simulated tools to verify the Planner,
Router, Worker, state persistence, reporting, and flag validation path.

## Running NYUCTF Experiments

Run one challenge:

```bash
conda run -n autopentest python run.py \
  --challenge "<challenge-name>" \
  --max-cycles 8 \
  --name single_demo
```

Run a random challenge:

```bash
conda run -n autopentest python run.py \
  --challenge __random__ \
  --split development \
  --max-cycles 8
```

Run all challenges in one category:

```bash
conda run -n autopentest python run.py \
  --category web \
  --run-all \
  --parallel-workers 5 \
  --max-cycles 25 \
  --name web_batch
```

Run a fixed subset:

```bash
conda run -n autopentest python run.py \
  --challenges "<challenge-a>" "<challenge-b>" \
  --parallel-workers 2 \
  --max-cycles 15 \
  --name subset_eval
```

Common options:

| Option | Default | Description |
| --- | --- | --- |
| `--challenge` | from `RUN_CONFIG` | Challenge name, `__all__`, or `__random__` |
| `--challenges` | unset | Fixed ordered challenge subset |
| `--run-all` | config-dependent | Run all selected challenges |
| `--split` | `development` | NYUCTF split: `development` or `test` |
| `--category` | unset | Category filter, such as `web`, `crypto`, `rev`, `pwn`, `forensics` |
| `--dataset` | unset | Custom dataset JSON path |
| `--max-cycles` | `25` in `RUN_CONFIG` | Maximum orchestration cycles per challenge |
| `--auto-max-cycles` | off | Estimate cycle budget from challenge files and services, capped at 30 |
| `--parallel-workers` | `5` in `RUN_CONFIG` | Concurrent challenge workers in batch mode |
| `--replicas` | `1` | Repeat count for a single selected challenge |
| `--sample-size` | unset | Sample a subset from the selected challenge list |
| `--sample-seed` | unset | Random seed for sampling |
| `--sample-strategy` | `random` | `random` or `category_round_robin` |
| `--container-image` | `ctfenv:latest` | Docker image used for tool execution |
| `--container-network` | `ctfnet` | Docker network for challenge containers |
| `--logdir` | `logs/<user>` | Batch log root |
| `--name` | `5.19_development_1` | Batch run name |
| `--knowledge-mode` | resolved by config/env | `enabled`, `offline`, or `disabled` |

## Generic `autopentest` CLI

You can also run a direct authorized assessment without the NYUCTF batch wrapper:

```bash
conda run -n autopentest autopentest run \
  --objective "Map and review the authorized web surface" \
  --scope "http://127.0.0.1:8080" \
  --output-root runs \
  --max-cycles 6
```

Available subcommands:

```bash
autopentest run       # Run one custom authorized assessment
autopentest demo      # Run the built-in demo configuration
autopentest selftest  # Run the deterministic local self-test
autopentest lab up    # Start a Docker Compose lab
autopentest lab down  # Stop a Docker Compose lab
autopentest lab health --url http://127.0.0.1:8080
```

## Output Artifacts

Batch results are written under:

```text
logs/<user>/<batch-name>/
```

Typical layout:

```text
logs/hy/web_batch/
├── _batch_summary.json          # Aggregated batch metrics
├── _batch_monitor.html          # Static HTML monitor
├── _batch_monitor.json          # JSON snapshot polled by the monitor
├── <challenge>.status.json      # Live per-challenge status
├── <challenge>.json             # Per-challenge result log
└── artifacts/
    └── <challenge>/
        └── run-xxxxxxxxxx/
            ├── config.json       # Runtime configuration
            ├── state.json        # Full RunState
            ├── evidence.json     # Evidence projection
            ├── events.log        # JSONL event stream
            ├── compact_log.json  # Compact timeline
            ├── compact_log.md    # Human/LLM-readable timeline
            ├── report.md         # Markdown report
            └── summary.json      # Metrics summary
```

Serve and open the batch monitor:

```bash
conda run -n autopentest python -m http.server 8765 -d logs/<user>/<batch-name>
```

Then visit:

```text
http://127.0.0.1:8765/_batch_monitor.html
```

## Knowledge Modes

The Planner sees an augmented context built by `IntelligenceAugmenter`. It
combines durable cross-run memory (loaded from `memory/` at the start of each
run) with optional networked retrieval from public security databases. The mode
flag controls what is allowed:

```bash
--knowledge-mode enabled
--knowledge-mode offline
--knowledge-mode disabled
```

| Mode | Behavior |
| --- | --- |
| `enabled` | Recall durable memory and fetch from CVE / MITRE ATT&CK / Exploit-DB |
| `offline` | Recall durable memory only; no outbound network requests |
| `disabled` | Skip both memory recall and network retrieval |

Durable memory is intentionally limited to `global` and `category` scope. There
is no per-challenge scope, so a previous run's notes for a specific challenge
cannot be retrieved as an answer when the same challenge runs again. Outbound
queries redact challenge identifiers, event names, and the validated flag
before leaving the host.

## Analysis Scripts

```bash
# Summarize dataset metadata
conda run -n autopentest python scripts/database_summary.py \
  --dataset-root ./LLM_CTF_Database \
  --output ./chal_data.json

# Render a legacy transcript
conda run -n autopentest python scripts/print_transcript.py \
  -t path/to/transcript.json

# Plot batch results
conda run -n autopentest python scripts/plot_results.py \
  logs/<user>/<batch-name>/

# Check whether a flag appears in run outputs
conda run -n autopentest python scripts/flag_in_output.py \
  logs/<user>/<batch-name>/
```

## Tests

Run the full test suite:

```bash
conda run -n autopentest python -m pytest
```

Run selected tests:

```bash
conda run -n autopentest python -m pytest tests/test_run_entrypoint.py
conda run -n autopentest python -m pytest tests/test_runtime_architecture.py
conda run -n autopentest python -m pytest tests/test_capability_gateway.py
```

The tests cover CLI arguments, planner behavior, tool capability contracts,
script execution guardrails, durable memory, knowledge augmentation, log
summaries, batch monitoring, runtime persistence, and architecture constraints.

## Design Notes

- **Multi-agent decomposition:** Planner handles strategy, Router handles
  assignment, and workers handle execution decisions.
- **Structured LLM output:** Critical model decisions are validated through
  Pydantic schemas and repaired at the gateway layer when possible.
- **Plugin-based execution:** Security tools share a common capability and
  output contract, making new tools easier to add.
- **State-driven loop:** RunState tracks assets, evidence, candidates, todos,
  execution records, result quality, and stop conditions.
- **Safety boundaries:** Authorized scope, Docker execution, command guards, and
  metadata validation reduce accidental misuse in lab environments.
- **Knowledge augmentation:** Durable memory recall is bounded to global and
  category scope; outbound network retrieval (CVE / ATT&CK / Exploit-DB) is
  gated by an explicit mode and redacts challenge-identifying tokens.
- **Observability:** Events, status snapshots, compact logs, reports, and token
  usage are written to disk.
- **Durable memory:** Trusted worker discoveries can be persisted at global or
  category scope for future runs. Per-challenge scope is intentionally not
  supported so memory cannot become a per-challenge answer oracle.

## Limitations

- Performance depends heavily on the chosen LLM and API reliability.
- Some unusual CTF tasks may need new tool plugins or prompt tuning.
- Complex interactive exploitation may require a larger `--max-cycles` budget.
- This framework targets CTF and lab workflows. It does not replace human
  authorization, risk assessment, or compliance review for real engagements.

## License

See `LICENSE`. When using NYUCTF or bundled security tools, also follow their
respective licenses, dataset rules, and lab usage restrictions.
