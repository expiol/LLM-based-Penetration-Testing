# Worker Registry

Workers are task roles: they inspect evidence, emit state updates, and send
planner signals. They do not queue follow-up tasks directly. Plugins are
execution tools. Keep that boundary intact when adding new behavior.

Workers call lower-level tools through `ToolCapability` values, not plugin
names. The `ToolGateway` maps each capability to the concrete implementation
registered in the execution plane.

Directory rules:

- Worker modules live directly under `killchain_docker/workers/`.
- `artifact/` is the only worker subpackage because it contains several
  routed artifact workers.
- Shared LLM guidance schemas live in `killchain_docker/reasoning/`.
- Script generation/execution is a tool capability (`script.execute`), not a
  worker or final phase.

To add a built-in worker:

1. Implement a `WorkerAgent` subclass under `killchain_docker/workers/`.
2. Add it to the matching domain module or package.
3. If it needs special constructor dependencies, add a custom `WorkerSpec` in
   that domain module; otherwise `worker_specs(...)` is enough.
4. Add a focused test for routing or report output.

`registry.py` only aggregates domain modules. It should not list individual
workers. `controller.build_runtime()` only calls `build_builtin_workers()`, so
downstream projects can replace this registry with their own worker set without
touching the orchestrator or plugins.
