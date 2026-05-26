"""Tests for RouterAgent assignment and summary behavior."""

from __future__ import annotations
import json
import unittest
from killchain_docker.llm.gateway import StaticLLMClient
from killchain_docker.orchestrator.agent_directory import AgentDirectory
from tests.queue_harness import todo_queue
from killchain_docker.orchestrator.router import RouterAgent
from killchain_docker.state.dispatch import DispatchIntent
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoItem, TodoPhase, WorkerResult
from killchain_docker.workers.runtime.agent import WorkerAgent
from killchain_docker.workers.personas.catalog import (
    ARTIFACT_PERSONA,
    EXPLOIT_PERSONA,
    RECON_PERSONA,
)
from killchain_docker.workers.runtime.worker import Worker


class _DirectoryWorker(WorkerAgent):
    supported_todo_kinds = ("todo",)

    def __init__(
        self,
        name: str,
        *,
        routing_summary: str = "",
        required_context_keys: tuple[str, ...] = (),
        allowed_capabilities: tuple[str, ...] = (),
        supported_dispatch_profiles: tuple[str, ...] = (),
    ) -> None:
        super().__init__()
        self.name = name
        self.routing_summary = routing_summary
        self.required_context_keys = required_context_keys
        self.allowed_capabilities = allowed_capabilities
        self.supported_dispatch_profiles = supported_dispatch_profiles

    def run(self, task: TodoItem, state: RunState) -> WorkerResult:
        del state
        return WorkerResult(
            todo_id=task.todo_id, worker_name=self.name, success=True, summary="ok"
        )


class RouterAgentTests(unittest.TestCase):
    def test_routes_with_agent_directory(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(goal="Review files", phase=TodoPhase.ANALYSIS)
        )
        captured: dict[str, object] = {}

        def respond(system_prompt: str, user_prompt: str):
            captured["system_prompt"] = system_prompt
            snapshot = json.loads(user_prompt)
            captured.update(snapshot)
            return {
                "assignments": [
                    {
                        "todo_id": todo.todo_id,
                        "worker_name": "artifact-worker",
                        "rationale": "file review",
                    }
                ],
                "rationale": "directory route",
            }

        router = RouterAgent(StaticLLMClient(respond))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        routing_summary="Static file analysis.",
                        required_context_keys=("files_root",),
                    )
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(decision.assignments[0].worker_name, "artifact-worker")
        system_prompt = str(captured["system_prompt"])
        self.assertNotIn("nmap", system_prompt)
        self.assertNotIn("binwalk", system_prompt)
        self.assertNotIn("curl headers", system_prompt)
        self.assertNotIn("binary exploitation", system_prompt)
        catalog = captured["agent_catalog"]
        self.assertEqual(catalog[0]["routing_summary"], "Static file analysis.")
        self.assertEqual(catalog[0]["required_context_keys"], ["files_root"])

    def test_routes_multiple_todos_to_different_workers(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        first = todo_queue(state).enqueue(TodoItem(goal="Map scope", priority=90))
        second = todo_queue(state).enqueue(TodoItem(goal="Review files", priority=80))
        router = RouterAgent(
            StaticLLMClient(
                [
                    {
                        "assignments": [
                            {
                                "todo_id": first.todo_id,
                                "worker_name": "recon-worker",
                                "rationale": "scope mapping",
                            },
                            {
                                "todo_id": second.todo_id,
                                "worker_name": "artifact-worker",
                                "rationale": "file review",
                            },
                        ],
                        "rationale": "parallel concerns, sequential execution",
                    }
                ]
            )
        )
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("recon-worker"), _DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(first.todo_id, "recon-worker"), (second.todo_id, "artifact-worker")],
        )

    def test_routes_only_one_focus_phase_per_round(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        recon = todo_queue(state).enqueue(
            TodoItem(goal="Collect baseline", phase=TodoPhase.RECON, priority=50)
        )
        exploit = todo_queue(state).enqueue(
            TodoItem(
                goal="Exploit confirmed issue", phase=TodoPhase.EXPLOIT, priority=100
            )
        )
        captured: dict[str, object] = {}

        def respond(system_prompt: str, user_prompt: str):
            del system_prompt
            snapshot = json.loads(user_prompt)
            captured.update(snapshot)
            ready = snapshot["ready_todos"]
            return {
                "assignments": [
                    {
                        "todo_id": ready[0]["todo_id"],
                        "worker_name": "recon-worker",
                        "rationale": "earliest phase first",
                    }
                ],
                "rationale": "single phase",
            }

        router = RouterAgent(StaticLLMClient(respond))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("recon-worker"), _DirectoryWorker("exploit-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [todo["todo_id"] for todo in captured["ready_todos"]], [recon.todo_id]
        )
        self.assertNotIn(
            exploit.todo_id, [todo["todo_id"] for todo in captured["ready_todos"]]
        )
        self.assertEqual(decision.assignments[0].todo_id, recon.todo_id)

    def test_llm_route_respected_for_analysis_tasks(self) -> None:
        """LLM routing decisions are trusted — no deterministic override."""
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Analyze bundled binary.",
                phase=TodoPhase.ANALYSIS,
                context={"binary_files": ["stfu"]},
            )
        )
        router = RouterAgent(
            StaticLLMClient(
                [
                    {
                        "assignments": [
                            {
                                "todo_id": todo.todo_id,
                                "worker_name": "artifact-worker",
                                "rationale": "file analysis",
                            }
                        ],
                        "rationale": "LLM route",
                    }
                ]
            )
        )
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("artifact-worker"), _DirectoryWorker("flag-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(decision.assignments[0].worker_name, "artifact-worker")

    def test_structural_scope_route_precedes_llm_fallback(self) -> None:
        """Grounded routing signals are handled before LLM fallback."""
        state = RunState(objective="Solve.", authorized_scope=[])
        scoped = todo_queue(state).enqueue(
            TodoItem(goal="Map scope", phase=TodoPhase.RECON, priority=90)
        )
        generic = todo_queue(state).enqueue(
            TodoItem(goal="Review notes", phase=TodoPhase.RECON, priority=80)
        )
        router = RouterAgent(
            StaticLLMClient(
                [
                    {
                        "assignments": [
                            {
                                "todo_id": scoped.todo_id,
                                "worker_name": "artifact-worker",
                                "rationale": "LLM chose artifact",
                            },
                            {
                                "todo_id": generic.todo_id,
                                "worker_name": "artifact-worker",
                                "rationale": "LLM chose artifact",
                            },
                        ],
                        "rationale": "LLM route",
                    }
                ]
            )
        )
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("recon-worker"), _DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(scoped.todo_id, "recon-worker"), (generic.todo_id, "artifact-worker")],
        )

    def test_web_recon_profile_text_does_not_route_as_file_context(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Perform web reconnaissance on the live service, register a test user, and inspect the profile workflow.",
                phase=TodoPhase.RECON,
                context={
                    "endpoint_id": "endpoint-1",
                    "target_base_url": "http://target.test",
                    "archive_path": "/workspace/bundle.tar",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("artifact-worker"), _DirectoryWorker("recon-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "recon-worker")],
        )

    def test_required_capability_routes_without_llm(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Inspect generated artifact.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "dispatch_intent": {
                        "profile": "artifact_analysis",
                        "required_capability": "artifact.triage",
                    },
                    "artifact_path": "/home/ctfplayer/ctf_files/out.bin",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker", allowed_capabilities=("artifact.triage",)
                    ),
                    _DirectoryWorker(
                        "recon-worker", allowed_capabilities=("artifact.triage",)
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )
        self.assertIn("artifact.triage", decision.assignments[0].rationale)

    def test_dispatch_profile_routes_without_llm(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Inspect generated image.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "dispatch_intent": {
                        "profile": "image_inspection",
                        "required_capability": "png.inspect",
                    },
                    "artifact_path": "/home/ctfplayer/ctf_files/out.png",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        allowed_capabilities=("png.inspect",),
                        supported_dispatch_profiles=("image_inspection",),
                    ),
                    _DirectoryWorker(
                        "recon-worker",
                        allowed_capabilities=("png.inspect",),
                        supported_dispatch_profiles=("scope_mapping",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )
        self.assertIn(
            "dispatch profile image_inspection", decision.assignments[0].rationale
        )

    def test_execution_closure_prefers_exploit_worker_for_active_exploit(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Execute the exploit against the authorized service, send the crafted payload, and recover a flag candidate.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "service_endpoint": "tcp://service.example:31337",
                    "dispatch_intent": {
                        "profile": "execution_closure",
                        "required_capability": "script.exec",
                    },
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        allowed_capabilities=("script.exec",),
                        supported_dispatch_profiles=("execution_closure",),
                    ),
                    _DirectoryWorker(
                        "exploit-worker",
                        allowed_capabilities=("script.exec",),
                        supported_dispatch_profiles=("execution_closure",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_local_execution_closure_keeps_artifact_worker_first(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Run a bounded local decoder over the artifact and recover a candidate.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "artifact_path": "/home/ctfplayer/ctf_files/blob.bin",
                    "dispatch_intent": {
                        "profile": "execution_closure",
                        "required_capability": "script.exec",
                    },
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        allowed_capabilities=("script.exec",),
                        supported_dispatch_profiles=("execution_closure",),
                    ),
                    _DirectoryWorker(
                        "exploit-worker",
                        allowed_capabilities=("script.exec",),
                        supported_dispatch_profiles=("execution_closure",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )

    def test_exploit_execution_continuation_prefers_exploit_worker(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Continue from grounded evidence and execute the next bounded step toward recovering a flag candidate.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "family": "execution-continuation",
                    "files_root": "/home/ctfplayer/ctf_files",
                    "dispatch_intent": {"profile": "execution_continuation"},
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        supported_dispatch_profiles=("execution_continuation",),
                    ),
                    _DirectoryWorker(
                        "exploit-worker",
                        supported_dispatch_profiles=("execution_continuation",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_pwn_exploit_profile_prefers_exploit_worker_over_file_signal(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Construct and execute exploit for a grounded memory-corruption finding.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "family": "pwn-exploit",
                    "files_root": "/home/ctfplayer/ctf_files",
                    "binary_path": "/home/ctfplayer/ctf_files/target",
                    "endpoint": "tcp://service.example:31337",
                    "dispatch_intent": {"profile": "pwn_exploit"},
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker", supported_dispatch_profiles=("pwn_exploit",)
                    ),
                    _DirectoryWorker(
                        "exploit-worker", supported_dispatch_profiles=("pwn_exploit",)
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_real_persona_catalog_routes_pwn_exploit_to_exploit_worker(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Construct and execute exploit for a grounded memory-corruption finding.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "family": "pwn-exploit",
                    "files_root": "/home/ctfplayer/ctf_files",
                    "binary_path": "/home/ctfplayer/ctf_files/target",
                    "endpoint": "tcp://service.example:31337",
                    "dispatch_intent": {"profile": "pwn_exploit"},
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [Worker(persona=ARTIFACT_PERSONA), Worker(persona=EXPLOIT_PERSONA)]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_exploit_phase_prefers_exploit_worker_over_passive_profile(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Construct and execute an exploit against the authorized service, then recover a flag candidate.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "scope": "tcp://service.example:31337",
                    "target_host": "service.example",
                    "target_port": 31337,
                    "files_root": "/home/ctfplayer/ctf_files",
                    "dispatch_intent": {
                        "profile": "scope_mapping",
                        "target_refs": {
                            "scope": "tcp://service.example:31337",
                            "files_root": "/home/ctfplayer/ctf_files",
                        },
                    },
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    Worker(persona=RECON_PERSONA),
                    Worker(persona=ARTIFACT_PERSONA),
                    Worker(persona=EXPLOIT_PERSONA),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_exploit_phase_prefers_exploit_worker_over_file_context(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://service.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Execute the next grounded exploit step against the authorized service.",
                phase=TodoPhase.EXPLOIT,
                context={
                    "files_root": "/home/ctfplayer/ctf_files",
                    "binary_path": "/home/ctfplayer/ctf_files/target",
                    "endpoint": "tcp://service.example:31337",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [Worker(persona=ARTIFACT_PERSONA), Worker(persona=EXPLOIT_PERSONA)]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "exploit-worker")],
        )

    def test_required_capability_filters_profile_candidate(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Inspect generated image.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "dispatch_intent": {
                        "profile": "image_inspection",
                        "required_capability": "png.inspect",
                    },
                    "artifact_path": "/home/ctfplayer/ctf_files/out.png",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        allowed_capabilities=("artifact.triage",),
                        supported_dispatch_profiles=("image_inspection",),
                    ),
                    _DirectoryWorker(
                        "recon-worker",
                        allowed_capabilities=("png.inspect",),
                        supported_dispatch_profiles=("image_inspection",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "recon-worker")],
        )

    def test_malformed_dispatch_refs_are_dropped(self) -> None:
        intent = DispatchIntent.from_context(
            {
                "dispatch_intent": {
                    "profile": "other",
                    "target_refs": "{'files': ['artifact.bin']}",
                },
                "path": "/home/ctfplayer/ctf_files/artifact.bin",
            }
        )
        self.assertEqual(intent.profile, "open")
        self.assertEqual(intent.target_refs, {})

    def test_stringified_dispatch_evidence_ids_are_normalized(self) -> None:
        intent = DispatchIntent.from_context(
            {"dispatch_intent": {"evidence_ids": "['evidence-a', 'evidence-b']"}}
        )
        self.assertEqual(intent.evidence_ids, ["evidence-a", "evidence-b"])

    def test_json_dispatch_evidence_ids_are_normalized(self) -> None:
        intent = DispatchIntent.from_context(
            {"dispatch_intent": {"evidence_ids": '["evidence-a", "evidence-b"]'}}
        )
        self.assertEqual(intent.evidence_ids, ["evidence-a", "evidence-b"])

    def test_scalar_dispatch_evidence_id_remains_single_reference(self) -> None:
        intent = DispatchIntent.from_context(
            {"dispatch_intent": {"evidence_ids": "evidence-a"}}
        )
        self.assertEqual(intent.evidence_ids, ["evidence-a"])

    def test_dispatch_intent_keeps_declared_profile(self) -> None:
        intent = DispatchIntent.from_context(
            {
                "family": "binary-dynamic",
                "scope": "tcp://target.example:31337",
                "dispatch_intent": {
                    "profile": "scope_mapping",
                    "required_capability": "shell.exec",
                },
            }
        )
        self.assertEqual(intent.profile, "scope_mapping")
        self.assertEqual(intent.required_capability, "shell.exec")

    def test_unknown_required_capability_does_not_block_generic_file_route(
        self,
    ) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Inspect generated artifact.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "dispatch_intent": {
                        "profile": "other",
                        "required_capability": "forensics.steg",
                    },
                    "artifact_path": "/home/ctfplayer/ctf_files/out.bin",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )

    def test_empty_llm_route_returns_no_valid_assignments(self) -> None:
        """When LLM returns no assignments, router returns empty decision (no raise)."""
        state = RunState(objective="Solve.", authorized_scope=[])
        todo_queue(state).enqueue(TodoItem(goal="Review notes", phase=TodoPhase.RECON))
        router = RouterAgent(
            StaticLLMClient([{"assignments": [], "rationale": "no useful assignment"}])
        )
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("recon-worker"), _DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(decision.assignments, [])
        self.assertIn("No valid", decision.rationale)

    def test_router_prompt_bounds_ready_todo_context(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        huge_text = "X" * 5000
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Route large context.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "crypto-decrypt",
                    "blob": huge_text,
                    "items": [huge_text for _ in range(20)],
                },
            )
        )
        captured: dict[str, object] = {}

        def respond(_system_prompt: str, user_prompt: str):
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "assignments": [
                    {
                        "todo_id": todo.todo_id,
                        "worker_name": "artifact-worker",
                        "rationale": "bounded context",
                    }
                ],
                "rationale": "bounded context",
            }

        router = RouterAgent(StaticLLMClient(respond))
        router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        ready = captured["snapshot"]["ready_todos"]
        context = ready[0]["context"]
        self.assertLessEqual(len(context["blob"]), 400)
        self.assertEqual(len(context["items"]), 8)
        self.assertNotIn("X" * 1000, json.dumps(captured["snapshot"]))

    def test_deterministic_flag_validation_route(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Validate candidate.",
                phase=TodoPhase.FLAG_VALIDATION,
                context={"candidate_flag": "flag{candidate_body}"},
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("flag-worker"), _DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "flag-worker")],
        )

    def test_flag_validation_phase_structurally_routes_to_flag_worker(self) -> None:
        """FLAG_VALIDATION phase todos are structurally routed to flag-worker without LLM."""
        state = RunState(
            objective="Solve.",
            authorized_scope=[],
            metadata={"challenge": {"flag_format": ""}},
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Validate recovered token.",
                phase=TodoPhase.FLAG_VALIDATION,
                context={"candidate_flag": "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME"},
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [_DirectoryWorker("flag-worker"), _DirectoryWorker("artifact-worker")]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "flag-worker")],
        )

    def test_candidate_recovery_routes_to_artifact_worker(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Re-derive a corrected flag candidate from original evidence.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "candidate-recovery",
                    "dispatch_intent": {"profile": "candidate_recovery"},
                    "files_root": "/home/ctfplayer/ctf_files",
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "artifact-worker",
                        supported_dispatch_profiles=("candidate_recovery",),
                    ),
                    _DirectoryWorker(
                        "flag-worker", supported_dispatch_profiles=("flag_validation",)
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )

    def test_binary_analysis_profile_prefers_artifact_worker(self) -> None:
        state = RunState(
            objective="Solve.", authorized_scope=["tcp://target.example:31337"]
        )
        todo = todo_queue(state).enqueue(
            TodoItem(
                goal="Analyze the local binary with GDB and disassembly to trace the exact execution path for the crashing input.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "binary-dynamic",
                    "artifact_path": "/home/ctfplayer/ctf_files/program",
                    "path": "/home/ctfplayer/ctf_files/program",
                    "scope": "tcp://target.example:31337",
                    "dispatch_intent": {
                        "profile": "binary_analysis",
                        "required_capability": "shell.exec",
                        "target_refs": {
                            "artifact_path": "/home/ctfplayer/ctf_files/program",
                            "scope": "tcp://target.example:31337",
                        },
                    },
                },
            )
        )
        router = RouterAgent(StaticLLMClient([]))
        decision = router.route(
            state,
            agent_directory=AgentDirectory.from_workers(
                [
                    _DirectoryWorker(
                        "recon-worker",
                        allowed_capabilities=("shell.exec",),
                        supported_dispatch_profiles=("scope_mapping",),
                    ),
                    _DirectoryWorker(
                        "artifact-worker",
                        allowed_capabilities=("shell.exec",),
                        supported_dispatch_profiles=("binary_analysis",),
                    ),
                ]
            ),
            max_assignments=5,
        )
        self.assertEqual(
            [(item.todo_id, item.worker_name) for item in decision.assignments],
            [(todo.todo_id, "artifact-worker")],
        )

    def test_short_results_are_returned_directly_without_llm_summary(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        router = RouterAgent(StaticLLMClient([]))
        summary = router.summarize_round(
            state,
            results=[
                WorkerResult(
                    todo_id="todo-1",
                    worker_name="recon-worker",
                    success=True,
                    summary="mapped",
                ),
                WorkerResult(
                    todo_id="todo-2",
                    worker_name="artifact-worker",
                    success=True,
                    summary="reviewed",
                ),
            ],
        )
        self.assertFalse(summary.used_llm)
        self.assertIn("mapped", summary.summary)
        self.assertEqual(len(summary.direct_results), 2)

    def test_long_results_trigger_llm_summary(self) -> None:
        state = RunState(objective="Solve.", authorized_scope=[])
        router = RouterAgent(
            StaticLLMClient(
                [
                    {
                        "summary": "compressed",
                        "direct_results": [],
                        "key_findings": ["important"],
                        "next_focus": "validate",
                        "used_llm": True,
                    }
                ]
            )
        )
        summary = router.summarize_round(
            state,
            results=[
                WorkerResult(
                    todo_id=f"todo-{idx}",
                    worker_name="artifact-worker",
                    success=True,
                    summary="x" * 1200,
                )
                for idx in range(4)
            ],
        )
        self.assertTrue(summary.used_llm)
        self.assertEqual(summary.summary, "compressed")


if __name__ == "__main__":
    unittest.main()
