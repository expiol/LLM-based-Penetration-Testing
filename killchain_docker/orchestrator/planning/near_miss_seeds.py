"""Near-miss evidence refinement seed planning."""

from __future__ import annotations
from killchain_docker.orchestrator.planning.schemas import PlannedTodo
from killchain_docker.orchestrator.todo.queue import TodoQueue
from killchain_docker.state.challenge_projection import ChallengeProjection
from killchain_docker.state.evidence_projection import EvidenceProjectionStore
from killchain_docker.state.run_state import RunState
from killchain_docker.state.todos import TodoPhase


class NearMissSeedPlanner:
    """Build follow-up todos for decode/decrypt near-miss evidence."""

    _CATEGORIES = frozenset(
        {"crypto", "cryptography", "forensics", "forensic", "stego", "steganography"}
    )
    _STRONG_TERMS = frozenset(
        {
            "base32",
            "base64",
            "cipher",
            "ciphertext",
            "codec",
            "decode",
            "decrypt",
            "encoding",
            "flag text",
            "hidden text",
            "keystream",
            "latin-1",
            "lfsr",
            "mojibake",
            "ocr",
            "plaintext",
            "plain text",
            "recover text",
            "stego",
            "xor",
        }
    )
    _WEAK_TERMS = frozenset({"ascii", "ascii-art", "garbled", "hex", "unicode"})
    _PROTOCOL_TERMS = frozenset(
        {
            "broken pipe",
            "connect",
            "connection",
            "http",
            "menu",
            "netcat",
            "prompt",
            "protocol",
            "raw tcp",
            "remote",
            "round ",
            "socket",
            "tcp",
            "telnet",
        }
    )

    def seed_todos(
        self, state: RunState, challenge_files: list[object]
    ) -> tuple[list[PlannedTodo], list[str]]:
        todos: list[PlannedTodo] = []
        notes: list[str] = []
        projection = EvidenceProjectionStore(state)
        for evidence_record in projection.near_miss_records():
            evidence_id = evidence_record.evidence_id
            evidence = evidence_record.evidence
            ctx = evidence_record.output_context
            near_misses = list(ctx.get("near_miss_candidates") or [])
            if not self._refinement_allowed(state, evidence, ctx, near_misses):
                continue
            dedupe_key = f"bootstrap:near-miss-refinement:{evidence_id}"
            if self._has_todo_key(state, dedupe_key):
                continue
            todos.append(
                PlannedTodo(
                    goal="Resolve near-miss output from grounded evidence.",
                    phase=TodoPhase.ANALYSIS,
                    priority=90,
                    context={
                        "family": "crypto-decrypt",
                        "dispatch_intent": {
                            "profile": "near_miss_repair",
                            "required_capability": "script.exec",
                        },
                        "evidence_ids": [evidence_id],
                        "near_miss_candidates": near_misses[:3],
                        "novelty_key": f"near-miss:{evidence_id}",
                        "files_root": str(
                            ctx.get("files_root") or "/home/ctfplayer/ctf_files"
                        ),
                        "challenge_files": challenge_files,
                    },
                    success_criteria=[
                        "Produce a valid flag candidate from the near-miss output."
                    ],
                    constraints=[
                        "Use only current-state evidence and authorized challenge artifacts."
                    ],
                    dedupe_key=dedupe_key,
                )
            )
            notes.append(
                f"Seeded near-miss refinement todo for evidence {evidence_id}."
            )
        return (todos, notes)

    @classmethod
    def _refinement_allowed(
        cls, state: RunState, evidence, ctx: dict, near_misses: list[object]
    ) -> bool:
        haystack = "\n".join(
            cls._evidence_terms(state, evidence, ctx, near_misses)
        ).lower()
        if any((term in haystack for term in cls._STRONG_TERMS)):
            return True
        if any((term in haystack for term in cls._PROTOCOL_TERMS)):
            return False
        if any((term in haystack for term in cls._WEAK_TERMS)):
            return True
        category = ChallengeProjection(state).category_raw()
        return category in cls._CATEGORIES

    @classmethod
    def _evidence_terms(
        cls, state: RunState, evidence, ctx: dict, near_misses: list[object]
    ) -> list[str]:
        texts = [
            evidence.summary,
            evidence.tool_name,
            evidence.capability or "",
            str(ctx.get("failure_kind") or ""),
            str(ctx.get("failure_detail") or ""),
            str(ctx.get("partial_reason") or ""),
            str(ctx.get("result_quality") or ""),
            str(ctx.get("stdout") or ""),
            str(ctx.get("stderr") or ""),
            cls._candidate_body(near_misses),
        ]
        todo = TodoQueue(state).get(evidence.task_id)
        if todo is not None:
            texts.extend(
                [
                    todo.goal,
                    todo.result_summary,
                    todo.error or "",
                    " ".join(todo.success_criteria),
                    " ".join(todo.constraints),
                    " ".join((str(value) for value in todo.context.values())),
                ]
            )
        return texts

    @staticmethod
    def _candidate_body(near_misses: list[object]) -> str:
        bodies: list[str] = []
        for item in near_misses[:3]:
            text = str(item)
            lines = text.splitlines()
            if lines and "preview:" in lines[0].lower():
                text = "\n".join(lines[1:])
            bodies.append(text)
        return "\n".join(bodies)

    @staticmethod
    def _has_todo_key(state: RunState, dedupe_key: str) -> bool:
        return TodoQueue(state).has_dedupe_key(dedupe_key)
