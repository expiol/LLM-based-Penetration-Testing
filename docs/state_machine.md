# State Machine

The workflow is a linear LangGraph state machine:

START -> recon -> analysis -> planning -> validation -> reporting -> END

## State schema

The state is a structured object with:

- `target`
- `discovered_assets`
- `findings`
- `plans`
- `evidence`
- `artifacts`
- `session_status`
- `recon_artifacts`

## Transition notes

- Each agent emits a stage event in `events.jsonl`.
- Tool executions emit `tool_call` events and persist evidence.
- Artifacts are written after the workflow completes to keep paths stable.
