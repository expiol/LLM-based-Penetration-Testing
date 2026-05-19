"""Tests for the high-level planner pipeline."""

from __future__ import annotations

import json
import unittest

from killchain_docker.llm import LLMClientError, StaticLLMClient
from killchain_docker.orchestrator.planning import (
    LLMPlanner,
    PlanningPipeline,
    PlannedTodo,
    PlannerDecision,
    TodoPhase,
)
from killchain_docker.orchestrator.policy import TodoPolicy
from killchain_docker.state import (
    EvidenceRecord,
    ExecutionRecord,
    Finding,
    FlagCandidate,
    Hypothesis,
    RunState,
    Severity,
    StateDelta,
    TodoItem,
    Vulnerability,
)


def _state(files: list[str] | None = None, scope: list[str] | None = None) -> RunState:
    return RunState(
        objective="Solve test challenge.",
        authorized_scope=list(scope or []),
        metadata={
            "challenge": {
                "name": "test",
                "category": "crypto",
                "flag_format": "flag{...}",
                "files": list(files or []),
            }
        },
    )


class PlanningPipelineSeedTests(unittest.TestCase):
    def test_seed_artifacts_and_scope_as_high_level_todos(self) -> None:
        state = _state(["solve.py"], ["http://example.test"])
        decision = PlanningPipeline().plan(state)
        goals = [todo.goal for todo in decision.todos]

        self.assertTrue(any("Inventory" in goal for goal in goals))
        self.assertTrue(any("Map authorized scope" in goal for goal in goals))
        self.assertTrue(all(not hasattr(todo, "task_type") for todo in decision.todos))

    def test_seed_flag_validation_for_grounded_candidate(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate

        decision = PlanningPipeline().plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(decision.todos[0].context["candidate_flag"], "flag{okay}")


class TodoPolicyNormalizationTests(unittest.TestCase):
    def test_file_goal_gets_canonical_files_context(self) -> None:
        state = _state(["solve.py"])
        todo = PlannedTodo(
            goal="Review source files for crypto weakness.",
            phase=TodoPhase.ANALYSIS,
        )
        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.context["files_root"], "/home/ctfplayer/ctf_files")
        self.assertEqual(todo.context["challenge_files"], ["solve.py"])
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_flag_recovery_file_analysis_stays_analysis(self) -> None:
        state = _state(["cipher.mpeg"])
        todo = PlannedTodo(
            goal="Perform deep analysis of the MPEG file to identify the cipher and recover the flag.",
            phase=TodoPhase.FLAG_VALIDATION,
        )
        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.context["files_root"], "/home/ctfplayer/ctf_files")
        self.assertEqual(todo.context["challenge_files"], ["cipher.mpeg"])
        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_candidate_flag_context_promotes_validation(self) -> None:
        todo = PlannedTodo(
            goal="Validate recovered candidate.",
            context={"candidate_flag": "flag{okay}"},
        )
        TodoPolicy.normalize(todo, _state([]))

        self.assertEqual(todo.phase, TodoPhase.FLAG_VALIDATION)

    def test_ungrounded_flag_validation_decryption_todo_becomes_analysis(self) -> None:
        state = _state(["stfu", "flag.stfu"])
        todo = PlannedTodo(
            goal=(
                "Write and execute a Python script that implements the LFSR-based "
                "decryption: read flag.stfu, reproduce the keystream, and print "
                "the recovered plaintext."
            ),
            phase=TodoPhase.FLAG_VALIDATION,
            context={
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": ["stfu", "flag.stfu"],
            },
        )

        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)

    def test_flag_format_template_is_not_a_concrete_candidate(self) -> None:
        state = _state(["stfu", "flag.stfu"])
        todo = PlannedTodo(
            goal=(
                "Implement the LFSR decryption and print the recovered plaintext "
                "in the expected flag{...} format."
            ),
            phase=TodoPhase.FLAG_VALIDATION,
        )

        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.phase, TodoPhase.ANALYSIS)
        self.assertNotIn("candidate_flag", todo.context)

    def test_state_flag_candidate_keeps_explicit_validation_phase(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        todo = PlannedTodo(
            goal="Validate the recovered candidate flag.",
            phase=TodoPhase.FLAG_VALIDATION,
        )

        TodoPolicy.normalize(todo, state)

        self.assertEqual(todo.phase, TodoPhase.FLAG_VALIDATION)

    def test_family_for_recognizes_list_files_as_artifact_inventory(self) -> None:
        family = TodoPolicy.family_for(
            "List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts."
        )
        self.assertEqual(family, "artifact-inventory")

    def test_family_for_overrides_explicit_other(self) -> None:
        family = TodoPolicy.family_for(
            "List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts.",
            context={"family": "other"},
        )
        self.assertEqual(family, "artifact-inventory")


class PlanningPipelineDedupTests(unittest.TestCase):
    def test_drops_duplicate_dedupe_keys(self) -> None:
        state = _state([])
        todos = [
            PlannedTodo(goal="A", dedupe_key="same"),
            PlannedTodo(goal="B", dedupe_key="same"),
        ]
        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(summary="dedupe", todos=todos),
        )

        self.assertEqual([todo.goal for todo in decision.todos], ["A"])

    def test_collapses_two_artifact_inventory_todos_with_different_keys(self) -> None:
        # Bootstrap seeds an artifact-inventory todo and the LLM also proposes
        # a paraphrased "list and inspect challenge files" recon todo.  Both
        # describe the same atomic recon family on the same files_root, so
        # the second should be dropped even though their dedupe_key strings
        # differ.
        state = _state(["stfu", "flag.stfu"])
        llm_todo = PlannedTodo(
            goal="List and inspect challenge files in /home/ctfplayer/ctf_files to identify available artifacts.",
            phase=TodoPhase.RECON,
            context={
                "files_root": "/home/ctfplayer/ctf_files",
                "challenge_files": ["stfu", "flag.stfu"],
            },
        )

        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(summary="dup", todos=[llm_todo]),
        )

        inventory_todos = [
            todo for todo in decision.todos
            if todo.context.get("family") == "artifact-inventory"
        ]
        self.assertEqual(len(inventory_todos), 1)
        self.assertTrue(any("dropped" in note for note in decision.notes))

    def test_partial_todo_blocks_same_dedupe_key_but_allows_new_key(self) -> None:
        state = _state([])
        partial = state.queue_todo(
            TodoItem(
                goal="Try LFSR decrypt.",
                phase=TodoPhase.ANALYSIS,
                context={"family": "crypto-decrypt"},
                dedupe_key="decrypt-same",
            )
        )
        partial.mark_running("artifact-worker")
        partial.mark_partial("script completed without a flag", "no candidate")

        decision = PlanningPipeline().merge(
            state,
            llm_decision=PlannerDecision(
                summary="retry",
                todos=[
                    PlannedTodo(
                        goal="Retry the same LFSR decrypt.",
                        phase=TodoPhase.ANALYSIS,
                        context={"family": "crypto-decrypt"},
                        dedupe_key="decrypt-same",
                    ),
                    PlannedTodo(
                        goal="Retry LFSR decrypt using newly extracted tap evidence.",
                        phase=TodoPhase.ANALYSIS,
                        context={"family": "crypto-decrypt", "novelty_key": "tap-evidence-1"},
                        dedupe_key="decrypt-with-tap-evidence",
                    ),
                ],
            ),
        )

        self.assertEqual([todo.dedupe_key for todo in decision.todos], ["decrypt-with-tap-evidence"])
        self.assertTrue(any("dropped 1 duplicate" in note for note in decision.notes))


class LLMPlannerTests(unittest.TestCase):
    def test_planner_combines_bootstrap_and_llm_todos(self) -> None:
        state = _state(["solve.py"])
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "review source",
                    "todos": [
                        {
                            "goal": "Review the bundled solve.py source for crypto weakness.",
                            "phase": "recon",
                            "priority": "high",
                            "context": {"seed_terms": ["solve.py"]},
                            "success_criteria": ["Read solve.py end to end."],
                            "constraints": ["Use local files only."],
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.summary, "review source")
        self.assertGreaterEqual(len(decision.todos), 2)
        self.assertEqual({todo.phase for todo in decision.todos}, {TodoPhase.RECON})
        llm_todo = next(todo for todo in decision.todos if "solve.py" in todo.goal)
        self.assertEqual(llm_todo.priority, 75)
        self.assertEqual(llm_todo.context["files_root"], "/home/ctfplayer/ctf_files")

    def test_planner_keeps_only_frontier_phase_from_mixed_llm_batch(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "mixed batch",
                    "todos": [
                        {
                            "goal": "Map authorized scope.",
                            "phase": "recon",
                            "priority": 90,
                            "context": {"scope": "http://example.test"},
                        },
                        {
                            "goal": "Exploit the discovered issue.",
                            "phase": "exploit",
                            "priority": 80,
                            "context": {"base_url": "http://example.test"},
                        },
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(_state([]))

        self.assertEqual([todo.phase for todo in decision.todos], [TodoPhase.RECON])
        self.assertTrue(any("phase gate" in note for note in decision.notes))

    def test_planner_continues_open_phase_before_downstream_phase(self) -> None:
        state = _state([])
        state.queue_todo(
            TodoItem(
                goal="Review source for vulnerability.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="open-analysis",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "premature exploit",
                    "todos": [
                        {
                            "goal": "Exploit reviewed vulnerability.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"vulnerability_id": "vuln-1"},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.todos, [])
        self.assertTrue(any("dropped 1" in note for note in decision.notes))

    def test_planner_drops_ungrounded_exploit_todo(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "ungrounded exploit",
                    "todos": [
                        {
                            "goal": "Exploit an assumed vulnerability.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"base_url": "http://example.test"},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(_state([]))

        self.assertEqual(decision.todos, [])
        self.assertTrue(any("ungrounded exploit" in note for note in decision.notes))

    def test_planner_drops_exploit_with_only_global_evidence(self) -> None:
        state = _state([])
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-inventory",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Inventory completed.",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "premature exploit",
                    "todos": [
                        {
                            "goal": "Exploit an assumed issue from prior output.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.todos, [])
        self.assertTrue(any("ungrounded exploit" in note for note in decision.notes))

    def test_planner_allows_exploit_with_explicit_evidence_id(self) -> None:
        state = _state([])
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-analysis",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Evidence shows controllable return address.",
            )
        )
        evidence_id = next(iter(state.evidence))
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "grounded exploit",
                    "todos": [
                        {
                            "goal": "Exploit the controllable return address.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"evidence_ids": [evidence_id]},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_drops_exploit_with_unknown_evidence_id(self) -> None:
        state = _state([])
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-analysis",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Evidence exists, but this is not the referenced record.",
            )
        )
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "ungrounded exploit",
                    "todos": [
                        {
                            "goal": "Exploit output that is not in state.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"evidence_ids": ["missing-evidence"]},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.todos, [])
        self.assertTrue(any("ungrounded exploit" in note for note in decision.notes))

    def test_planner_allows_exploit_with_existing_hypothesis_id(self) -> None:
        state = _state([])
        hypothesis = Hypothesis(title="Stack offset can overwrite the return address.")
        state.apply_state_delta(StateDelta(hypotheses=[hypothesis]))
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "hypothesis-driven exploit",
                    "todos": [
                        {
                            "goal": "Test exploit payload for the return-address hypothesis.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"hypothesis_id": hypothesis.hypothesis_id},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_drops_exploit_with_unreferenced_finding(self) -> None:
        state = _state([])
        state.upsert_finding(Finding(finding_id="finding-1", title="SQLi", severity=Severity.HIGH))
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "missing finding ref",
                    "todos": [
                        {
                            "goal": "Exploit the discovered finding.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(decision.todos, [])
        self.assertTrue(any("ungrounded exploit" in note for note in decision.notes))

    def test_planner_allows_exploit_with_existing_finding_id(self) -> None:
        state = _state([])
        state.upsert_finding(Finding(finding_id="finding-1", title="SQLi", severity=Severity.HIGH))
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "finding-driven exploit",
                    "todos": [
                        {
                            "goal": "Exploit the SQL injection finding.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {"finding_id": "finding-1"},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_allows_exploit_with_typed_vulnerability_state(self) -> None:
        state = _state([])
        state.apply_state_delta(
            StateDelta(vulnerabilities=[Vulnerability(title="Controllable return address.")])
        )
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "vulnerability-driven exploit",
                    "todos": [
                        {
                            "goal": "Exploit the controllable return address.",
                            "phase": "exploit",
                            "priority": 90,
                            "context": {},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.EXPLOIT)

    def test_planner_respects_stop_run(self) -> None:
        planner = LLMPlanner(
            StaticLLMClient([
                {"summary": "done", "todos": [], "notes": [], "stop_run": True}
            ])
        )
        self.assertTrue(planner.plan(_state([])).stop_run)

    def test_planner_raises_when_llm_fails(self) -> None:
        planner = LLMPlanner(StaticLLMClient([]))

        with self.assertRaises(LLMClientError):
            planner.plan(_state(["solve.py"]))

    def test_planner_keeps_mislabelled_flag_recovery_analysis_todo(self) -> None:
        state = _state(["cipher.mpeg"])
        bootstrap = state.queue_todo(
            TodoItem(
                goal="Inventory and classify bundled challenge files.",
                phase=TodoPhase.RECON,
                dedupe_key="bootstrap:artifact-inventory",
            )
        )
        bootstrap.mark_completed("one MPEG-like text artifact found")
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "analyze MPEG",
                    "todos": [
                        {
                            "goal": "Perform deep analysis of the MPEG file to identify the cipher and recover the flag.",
                            "phase": "flag_validation",
                            "priority": 90,
                            "context": {"challenge_files": ["cipher.mpeg"]},
                            "success_criteria": ["Produce a decrypted plaintext or concrete flag candidate."],
                            "constraints": ["Use local files only."],
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)

    def test_planner_prioritizes_grounded_flag_validation_candidate(self) -> None:
        state = _state([])
        candidate = FlagCandidate(value="flag{okay}", source="artifact.triage")
        state.flag_candidates[candidate.candidate_id] = candidate
        planner = LLMPlanner(
            StaticLLMClient([
                {
                    "summary": "more analysis",
                    "todos": [
                        {
                            "goal": "Review another artifact before flag recovery.",
                            "phase": "analysis",
                            "priority": 80,
                            "context": {},
                        }
                    ],
                    "notes": [],
                    "stop_run": False,
                }
            ])
        )

        decision = planner.plan(state)

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.FLAG_VALIDATION)
        self.assertEqual(decision.todos[0].context["candidate_flag"], "flag{okay}")

    def test_planner_keeps_flag_format_decryption_todo_as_analysis(self) -> None:
        def responder(_system_prompt: str, _user_prompt: str) -> dict[str, object]:
            return {
                "summary": "recover plaintext",
                "todos": [
                    {
                        "goal": (
                            "Write and execute a Python script that implements the LFSR "
                            "decryption and prints the recovered flag{...} plaintext."
                        ),
                        "phase": "flag_validation",
                        "priority": 80,
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        decision = LLMPlanner(StaticLLMClient(responder)).plan(_state([]))

        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)
        self.assertFalse(any("ungrounded flag_validation" in note for note in decision.notes))

    def test_planner_prompt_includes_stagnation_signals_without_blocking(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "summary": "try another analysis",
                "todos": [
                    {
                        "goal": "Try a different LFSR analysis path.",
                        "phase": "analysis",
                        "priority": 70,
                        "context": {"challenge_files": ["flag.enc"]},
                    }
                ],
                "notes": [],
                "stop_run": False,
            }

        state = _state([])
        partial = state.queue_todo(
            TodoItem(
                goal="Decrypt the ciphertext and recover the flag.",
                phase=TodoPhase.ANALYSIS,
                dedupe_key="decrypt-once",
            )
        )
        partial.mark_running("exploit-worker")
        partial.mark_partial(
            "Script execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
            "script exited successfully but no flag candidate was recovered",
        )
        planner = LLMPlanner(StaticLLMClient(responder))

        decision = planner.plan(state)

        signals = captured["snapshot"]["stagnation_signals"]  # type: ignore[index]
        self.assertEqual(signals["todo_status_counts"]["partial"], 1)  # type: ignore[index]
        self.assertEqual(len(signals["partial_todos"]), 1)  # type: ignore[index]
        self.assertEqual(len(decision.todos), 1)
        self.assertEqual(decision.todos[0].phase, TodoPhase.ANALYSIS)

    def test_planner_prompt_includes_recent_tool_evidence_context(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {
                "summary": "use existing evidence",
                "todos": [],
                "notes": [],
                "stop_run": True,
            }

        state = _state([])
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-script",
                capability="script.exec",
                tool_name="script_exec",
                mode="local_command",
                summary="Script execution ran without recovering a flag: exit code 0, 0 flag candidate(s).",
                extracted={
                    "output_context": {
                        "returncode": 0,
                        "result_quality": "partial_no_candidate",
                        "partial_reason": "script exited successfully but no flag candidate was recovered",
                        "failure_kind": "no_candidate",
                        "failure_detail": "script exited successfully but no flag candidate was recovered",
                        "stdout": (
                            "Raw hex of first 16 bytes: 535446556aab0223201f1e0a00008540\n"
                            "LE uint32 at 4-7: 587377514\n"
                            "LE uint32 at 8-11: 169746208\n"
                            "LE uint32 at 12-15: 1082458112\n"
                        ),
                        "flag_candidates": [],
                    }
                },
            )
        )
        state.upsert_evidence(
            EvidenceRecord(
                task_id="todo-disasm",
                capability="shell.exec",
                tool_name="shell_exec",
                mode="local_command",
                summary="Binary disassembly completed for 1 file(s): 1 function(s) kept, 0 flag candidate(s).",
                extracted={
                    "output_context": {
                        "inspected_binaries": ["stfu"],
                        "disassembly": {
                            "stfu": {
                                "binary_traits": {
                                    "arch": "i386",
                                    "stripped": True,
                                    "go_like": False,
                                },
                                "function_count_total": 23,
                                "function_count_kept": 1,
                                "disassembly_truncated": True,
                                "analysis_windows": [
                                    "804884d: xor ebx,eax\n804884f: and eax,0x1\n8048852: mov DWORD PTR [ebp-0xc],eax"
                                ],
                                "functions": [
                                    {
                                        "name": ".text",
                                        "size_lines": 181,
                                        "truncated": True,
                                        "xref_strings": ["Supplied tap values out of range", "STFU"],
                                        "disassembly": "08048660 <.text>:\n 804884d: xor ebx,eax",
                                    }
                                ],
                            }
                        },
                        "flag_candidates": [],
                    }
                },
            )
        )

        LLMPlanner(StaticLLMClient(responder)).plan(state)

        context = captured["snapshot"]["recent_evidence_context"]  # type: ignore[index]
        self.assertIsInstance(context, list)
        rendered = json.dumps(context)
        self.assertIn("535446556aab0223201f1e0a00008540", rendered)
        self.assertIn("partial_no_candidate", rendered)
        self.assertIn("no_candidate", rendered)
        # Shell evidence goes through generic context; verify top-level keys kept
        self.assertIn("inspected_binaries", rendered)
        self.assertIn("stfu", rendered)
        contract = captured["snapshot"]["planning_contract"]  # type: ignore[index]
        self.assertIn("/tmp files", contract["evidence_context_rule"])  # type: ignore[index]

    def test_planner_prompt_includes_structured_rejected_candidates(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "stop", "todos": [], "notes": [], "stop_run": True}

        state = _state([])
        state.apply_state_delta(
            StateDelta(
                flag_candidates=[
                    FlagCandidate(value="flag{os.strerror(err) if err else 'Success'}", source="script")
                ]
            )
        )

        LLMPlanner(StaticLLMClient(responder)).plan(state)

        rejected = captured["snapshot"]["rejected_flag_candidates"]  # type: ignore[index]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["reason"], "invalid_candidate_shape")

    def test_planner_prompt_bounds_mutable_state_sections(self) -> None:
        captured: dict[str, object] = {}

        def responder(_system_prompt: str, user_prompt: str) -> dict[str, object]:
            captured["snapshot"] = json.loads(user_prompt)
            return {"summary": "bounded", "todos": [], "notes": [], "stop_run": True}

        state = _state([])
        huge_text = "X" * 5000
        state.queue_todo(
            TodoItem(
                goal="Analyze large generated context.",
                phase=TodoPhase.ANALYSIS,
                context={
                    "family": "crypto-decrypt",
                    "blob": huge_text,
                    "items": [f"item-{index}-" + huge_text for index in range(20)],
                    "nested": {"payload": huge_text},
                },
                dedupe_key="huge-context",
            )
        )
        state.working_memory["huge"] = huge_text
        state.execution_log.append(
            ExecutionRecord(
                task_id="todo-huge",
                worker_name="artifact-worker",
                success=False,
                summary=huge_text,
                error=huge_text,
            )
        )

        LLMPlanner(StaticLLMClient(responder)).plan(state)

        snapshot = captured["snapshot"]
        todo_context = snapshot["todos"][0]["context"]  # type: ignore[index]
        self.assertLessEqual(len(todo_context["blob"]), 400)
        self.assertIn("truncated", todo_context["blob"])
        self.assertEqual(len(todo_context["items"]), 8)
        self.assertLessEqual(len(todo_context["nested"]["payload"]), 400)
        self.assertLessEqual(len(snapshot["working_memory"]["huge"]), 400)  # type: ignore[index]
        execution_log = snapshot["recent_execution_log"]  # type: ignore[index]
        self.assertLessEqual(len(execution_log[0]["summary"]), 360)
        self.assertLessEqual(len(execution_log[0]["error"]), 260)
        self.assertNotIn("X" * 1000, json.dumps(snapshot))


class PlannedTodoPriorityTests(unittest.TestCase):
    def test_string_priority_is_coerced(self) -> None:
        self.assertEqual(PlannedTodo(goal="x", priority="high").priority, 75)
        self.assertEqual(PlannedTodo(goal="x", priority="60").priority, 60)


if __name__ == "__main__":
    unittest.main()
