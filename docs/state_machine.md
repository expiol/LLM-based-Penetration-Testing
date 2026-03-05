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
- `session_status`

Additional fields (like `recon_artifact`) are included to support internal flow.

## Transition notes

- Each agent stage records an event and updates the state.
- Tool executions are captured as evidence with JSON artifacts.
- Errors raise explicit exceptions and end the run with failure status.
