# Worker Registry

The runtime has five high-level persona workers:

- `ReconWorker`
- `ArtifactWorker`
- `WebWorker`
- `ExploitWorker`
- `FlagWorker`

The planner emits high-level todos. `RouterAgent` assigns each ready todo to
one persona worker. Workers may choose lower-level `ToolCapability` calls
through `ToolGateway`, but they return only structured `WorkerResult` objects
and suggested todos. They do not mutate the queue directly.

Directory rules:

- Persona workers live in `persona.py`.
- `registry.py` exposes only the built-in persona set.
- Shared low-level tool behavior stays under `killchain_docker/tools/`.
- Flag extraction and other LLM/tool helper schemas live in
  `killchain_docker/reasoning/`.
