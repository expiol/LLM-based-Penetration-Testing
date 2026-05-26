# LLM-based Penetration Testing

A multi-agent LLM-driven killchain framework for autonomous CTF solving and security assessment, built on the [NYUCTF](https://github.com/NYU-LLM-CTF/nyuctf) dataset.

## Architecture

```
Planner (LLM) ──→ Router (LLM) ──→ Persona Workers ──→ Tool Plugins
    │                                    │                    │
    │  proposes todos                    │  selects tool      │  executes in
    │  with goals/context                │  capability        │  Docker container
    ▼                                    ▼                    ▼
RunState ◄──────── Evidence ◄─────── Parsed Output ◄──── Container stdout
```

**Orchestration loop:** Each cycle, the Planner observes the full run state and proposes high-level todos. The Router assigns todos to specialized workers. Workers select concrete tool capabilities, execute them inside a Docker container, and merge results back into shared state.

**Persona Workers:**
- `recon-worker` — scope mapping, service discovery
- `artifact-worker` — file analysis, binary disassembly, script execution
- `web-worker` — HTTP probing, form interaction, path enumeration
- `exploit-worker` — vulnerability probes, exploit scripts, credential testing
- `flag-worker` — flag candidate validation with fuzzy matching

**Tool Plugins (22+):** binary disassembly, binary execution, script execution, HTTP metadata/content/forms/paths, credential harvesting/login, archive/sqlite/pcap review, exploit probes, flag harvesting, and more.

## Setup

```bash
# Clone and install
git clone https://github.com/expiol/LLM-based-Penetration-Testing.git
cd LLM-based-Penetration-Testing

# Build Docker environment and install package
bash setup.sh

# Configure LLM provider
cp configs/llm_gateway.json.example configs/llm_gateway.json
# Edit configs/llm_gateway.json with your API key and model
```

### LLM Configuration

Edit `configs/llm_gateway.json`:

```json
{
  "provider": "openai_compatible",
  "base_url": "https://api.openai.com/v1",
  "api_key": "sk-...",
  "default_model": "gpt-4o",
  "timeout_s": 60,
  "max_retries": 4,
  "max_completion_tokens": 16384
}
```

Supports any OpenAI-compatible provider (OpenAI, DeepSeek, Together, Groq, OpenRouter).

## Usage

```bash
# Run a single challenge
conda run -n autopentest python run.py --challenge "<challenge-name>"

# Run all challenges in a category
conda run -n autopentest python run.py --category crypto --run-all

# Run with custom cycle limit
conda run -n autopentest python run.py --challenge "<challenge-name>" --max-cycles 15

# Run a random challenge
conda run -n autopentest python run.py --challenge __random__
```

### Common Flags

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--dataset` | NYUCTF path | Dataset JSON file |
| `--split` | `development` | Dataset split (`test` / `development`) |
| `--category` | unset | Filter by category (`web`, `crypto`, `rev`, `pwn`, `forensics`, `misc`) |
| `--max-cycles` | `8` | Maximum orchestrator cycles per challenge |
| `--auto-max-cycles` | off | Scale the cycle budget from challenge files/scope instead of treating `--max-cycles` as a hard limit |
| `--parallel-workers` | `1` | Concurrent challenge workers for `--run-all` |
| `--container-image` | `ctfenv:latest` | Docker image for execution |
| `--container-network` | `ctfnet` | Docker network name |
| `--logdir` | `logs/<user>` | Batch logs and live monitor output |
| `--output-root` | unset | Artifact root; defaults under the run log directory |

## Output

Results are written to `logs/<user>/<batch_name>/`:

```
logs/hy/5.15_development_3/
├── _batch_summary.json          # Aggregated metrics
├── _batch_monitor.html          # Static live dashboard for batch progress
├── _batch_monitor.json          # Dashboard snapshot, refreshed during runs
├── example-challenge.status.json # Current stage for one challenge process
├── example-challenge.json        # Full execution trace
└── artifacts/
    └── example-challenge/
        └── run-986b921320/
            ├── config.json      # Challenge config
            ├── events.log       # JSONL cycle-by-cycle structured events
            ├── evidence.json    # Collected evidence
            ├── compact_log.json # Lightweight live run timeline
            ├── compact_log.md   # Human/LLM readable run timeline
            ├── report.md        # Human-readable report
            ├── state.json       # Complete run state
            └── summary.json     # Execution metrics
```

Open `_batch_monitor.html` from the batch log directory through any static file
server rooted at that directory to watch active challenge runs, worker process
status, reported pid/thread ids, current todo, latest event, current status
files, and completed artifact links refresh in place. The dashboard polls JSON
status files; before a child worker writes its own status, parallel runs are
shown as scheduled rather than as a real worker thread.
For example:

```bash
conda run -n autopentest python -m http.server 8765 -d logs/<run-name>
```

Then open `http://127.0.0.1:8765/_batch_monitor.html`.

## RAG Modes

Set `AUTOPENTEST_RAG_MODE` to control writeup augmentation:

- `oracle`: use the temporary direct-oracle provider, which reads the local
  corpus writeup for the current challenge and tests whether the execution
  pipeline can turn a correct technical direction into a validated result.
- `strict`: exclude same challenge and same event hits for answer-excluded generalization runs.
- `disabled`: omit RAG hints entirely.

Only these three mode names are accepted; invalid values fail fast instead of
silently falling back to oracle mode.

Retrieved writeups are used as method priors only. Literal flag-like values
are redacted before planner prompt injection.

RAG is wired through `killchain_docker.rag.providers.RagProvider`, so the
current oracle-backed implementation can be replaced later with a security
knowledge provider without changing planner or worker code.

`conda run -n autopentest python run.py` and
`conda run -n autopentest autopentest run` also accept `--rag-mode`, which is
recorded in `config.json`, per-run summaries, status files, and batch
summaries. Use `--rag-mode oracle` as a first-round execution-capability check:
the planner stays general, and retrieved hints are treated as technical context
that must still be executed and validated from local/runtime evidence. Use
`--rag-mode strict` or a domain knowledge corpus for the answer-excluded pass
that better matches the formal test collection.
For direct `autopentest run` or `autopentest demo` usage outside batch mode,
pass `--status-path <path>.status.json` when a live status file is needed.

To run the same benchmark slice in both modes and collect one comparison
manifest:

```bash
conda run -n autopentest python scripts/run_rag_ablation.py \
  --challenge "<challenge-name>" \
  --max-cycles 1 \
  --logdir logs/rag_ablation \
  --name smoke \
  --audit
```

For a reproducible named subset before running a full split:

```bash
conda run -n autopentest python scripts/run_rag_ablation.py \
  --challenges "<challenge-a>" "<challenge-b>" \
  --modes oracle strict disabled \
  --max-cycles 8 \
  --logdir logs/rag_ablation \
  --name subset_rag \
  --audit
```

For the full development split:

```bash
conda run -n autopentest python scripts/run_rag_ablation.py \
  --run-all \
  --split development \
  --parallel-workers 5 \
  --max-cycles 25 \
  --logdir logs/rag_ablation \
  --name development_rag \
  --audit
```

The manifest is written to
`logs/rag_ablation/<name>/_rag_ablation.json`, with per-mode batch summaries
and `_batch_monitor.html` files under sibling `<name>_<mode>` directories.
By default, run artifacts stay under those per-mode log directories so monitor
artifact links work from the same static file server root.
The ablation runner uses the current Python interpreter for child runs, so
launching it through `conda run -n autopentest` keeps the full flow in that
environment. `--audit` writes `_rag_ablation_audit.json` next to the manifest.
You can also audit an existing manifest directly:

```bash
conda run -n autopentest python scripts/audit_rag_ablation.py logs/rag_ablation/development_rag/_rag_ablation.json
```

The audit verifies that the selected modes finished, summaries and monitors
agree, status files and event JSONL are readable, RAG payloads match their
mode, and strict mode did not retrieve challenge-identical or same-event hints.

## Logging

Runtime logs use the standard Python `logging` module. Context passed through
`extra={...}` is rendered by default, and `AUTOPENTEST_LOG_JSON=1` switches
process logs to JSON lines. Per-run `events.log` is also JSONL and includes
timestamp, level, event type, process/thread ids and names, run id, challenge
id, and the human-readable event message.
Each live `*.status.json` file mirrors the same run id, pid/thread id/name,
latest event summary, current todo, RAG status, and monitor-safe artifact
links.
During long LLM calls a lightweight heartbeat refreshes `updated_at` while
`state_updated_at` remains the last actual RunState change timestamp.
The dashboard shows both ages and marks active rows stale if the heartbeat
stops updating.

### Analysis Scripts

```bash
conda run -n autopentest python scripts/database_summary.py --dataset-root ./LLM_CTF_Database --output ./chal_data.json
conda run -n autopentest python scripts/print_transcript.py -t path/to/legacy_transcript.json
conda run -n autopentest python scripts/plot_results.py logs/hy/batch_name/
```

## Key Design Decisions

- **Backlog-first planning:** The Planner creates work only when no ready todo is queued; the Router and workers consume the current plan before asking for more.
- **Bounded script correction:** Workers may make one deterministic corrective script attempt for flag-recovery failures, with structured failure context.
- **Bounded process lifecycle:** Tool plugins and Docker helpers share one subprocess runner with bounded output capture, stdin delivery, timeout reporting, and process-group cleanup.
- **Gateway-owned structured output repair:** Common LLM JSON failures around source-code strings are repaired at the gateway before schema validation, keeping workers focused on typed decisions.
- **Typed LLM failures:** LLM errors carry explicit failure kinds (connection, timeout, schema validation, rate limit, config) so retry and batch reporting are not driven by free-form exception text.
- **Structured novelty gates:** Cooldown escape requires new current-state `evidence_ids` or `hypothesis_id(s)`; `novelty_key` only labels the approach, and rephrased todo text is not progress.
- **Decision-owned tool metadata:** Required executable metadata (`command`, `script_code`, paths, targets) comes from the current tool decision; todo context can only supply optional defaults.
- **Forced Pivot:** After N rounds without progress, stalled approach families are banned and the planner must try a fundamentally different attack vector
- **RAG augmentation:** A replaceable provider supplies technical hints to the planner; the current oracle provider directly reads local writeups, with decontamination when they appear misleading.
- **Progress policy:** Family-based cooldown and novelty detection prevent infinite loops on the same approach
- **Structured failure evidence:** Rejected flag candidates, no-candidate scripts, bytes/text errors, and network pipe failures are recorded as typed state/evidence signals.
- **Working memory:** Key discoveries persist across cycles as established facts

## Requirements

- Python ≥ 3.11
- Docker
- An OpenAI-compatible LLM API endpoint

## License

MIT License — NYU Tandon School of Engineering and NYU Abu Dhabi.
