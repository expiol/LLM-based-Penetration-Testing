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
python run.py --challenge "2013f-cry-stfu"

# Run all challenges in a category
python run.py --category crypto --run-all

# Run with custom cycle limit
python run.py --challenge "2013f-web-historypeats" --max-cycles 15

# Run a random challenge
python run.py --challenge __random__
```

### Configuration (in `run.py`)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `DATASET` | NYUCTF path | Dataset JSON file |
| `SPLIT` | `"development"` | Dataset split (`test` / `development`) |
| `CATEGORY` | `None` | Filter by category (web, crypto, rev, pwn, forensics, misc) |
| `MAX_CYCLES` | `25` | Maximum orchestrator cycles per challenge |
| `CONTAINER_IMAGE` | `"ctfenv:latest"` | Docker image for execution |
| `CONTAINER_NETWORK` | `"ctfnet"` | Docker network name |

## Output

Results are written to `logs/<user>/<batch_name>/`:

```
logs/hy/5.15_development_3/
├── _batch_summary.json          # Aggregated metrics
├── 2013f-cry-stfu.json          # Full execution trace
└── artifacts/
    └── 2013f-cry-stfu/
        └── run-986b921320/
            ├── config.json      # Challenge config
            ├── events.log       # Cycle-by-cycle trace
            ├── evidence.json    # Collected evidence
            ├── report.md        # Human-readable report
            ├── state.json       # Complete run state
            └── summary.json     # Execution metrics
```

### Analysis Scripts

```bash
python scripts/database_summary.py logs/hy/batch_name/
python scripts/print_transcript.py logs/hy/batch_name/artifacts/challenge/run-*/
python scripts/plot_results.py logs/hy/batch_name/
```

## Key Design Decisions

- **Reflexion pattern:** Workers retry failed scripts with error analysis injected as context
- **Forced Pivot:** After N rounds without progress, stalled approach families are banned and the planner must try a fundamentally different attack vector
- **RAG augmentation:** Related CTF writeups are retrieved and provided to the planner as hints (with decontamination when they appear misleading)
- **Progress policy:** Family-based cooldown and novelty detection prevent infinite loops on the same approach
- **Working memory:** Key discoveries persist across cycles as established facts

## Requirements

- Python ≥ 3.10
- Docker
- An OpenAI-compatible LLM API endpoint

## License

MIT License — NYU Tandon School of Engineering and NYU Abu Dhabi.
