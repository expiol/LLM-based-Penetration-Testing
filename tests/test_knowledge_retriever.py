"""Tests for the knowledge / RAG module.

Uses :class:`StubEmbedder` so the suite never downloads the 67 MB ONNX model
and never touches ``~/.cache/fastembed``.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from killchain_docker.batch.dataset import challenge_metadata
from killchain_docker.knowledge import KnowledgeAugmenter, public_rag_payload
from killchain_docker.knowledge.corpus import (
    KnowledgeEntry,
    extract_solution_sketch,
    load_corpus,
)
from killchain_docker.knowledge.embedder import (
    CachedEmbeddingMatrix,
    StubEmbedder,
)
from killchain_docker.knowledge.retriever import (
    KnowledgeRetriever,
    RetrievalHit,
    actionable_oracle_challenge_ids,
    oracle_context_status,
    rag_mode,
)
from killchain_docker.llm import StaticLLMClient
from killchain_docker.orchestrator.planning.strategy import PlanStrategy
from killchain_docker.state import RunState


def _entry(
    challenge_id: str,
    *,
    name: str,
    category: str,
    description: str,
    solution: str,
    files: list[str] | None = None,
    year: str = "2013",
    event: str = "CSAW-Quals",
) -> KnowledgeEntry:
    return KnowledgeEntry(
        challenge_id=challenge_id,
        year=year,
        event=event,
        category=category,
        name=name,
        description=description,
        files=files or [],
        writeup="",
        solution_sketch=solution,
    )


class ExtractSolutionSketchTests(unittest.TestCase):
    def test_pulls_solution_block_only(self):
        readme = (
            "# Title\n"
            "## Description\nfoo\n"
            "## Solution\nDecode XOR with key 0x42.\n"
            "## Setup\nStart docker.\n"
        )
        body = extract_solution_sketch(readme)
        self.assertEqual(body, "Decode XOR with key 0x42.")

    def test_returns_empty_when_missing(self):
        self.assertEqual(extract_solution_sketch("# x\n## Description\nbar\n"), "")

    def test_case_insensitive(self):
        readme = "## SOLUTION\nuse RSA factoring\n"
        self.assertEqual(extract_solution_sketch(readme), "use RSA factoring")


class LoadCorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _make_chal(
        self,
        cid: str,
        *,
        rel: str,
        name: str,
        category: str,
        description: str,
        solution: str,
        files: list[str],
        extra_files: dict[str, str] | None = None,
    ) -> dict:
        chal_dir = self.tmp / rel
        chal_dir.mkdir(parents=True)
        (chal_dir / "challenge.json").write_text(
            json.dumps(
                {"name": name, "category": category, "description": description, "files": files}
            ),
            encoding="utf-8",
        )
        (chal_dir / "README.md").write_text(
            f"## Description\n{description}\n## Solution\n{solution}\n## Setup\nx\n",
            encoding="utf-8",
        )
        for name, body in (extra_files or {}).items():
            (chal_dir / name).write_text(body, encoding="utf-8")
        return {
            "year": "2013",
            "event": "CSAW-Quals",
            "category": category,
            "challenge": name,
            "path": rel,
        }

    def test_loads_all_entries_with_solution_sketch(self):
        index = {
            "alpha": self._make_chal(
                "alpha",
                rel="development/2013/CSAW-Quals/crypto/alpha",
                name="alpha",
                category="crypto",
                description="LFSR-based cipher with 16-byte header",
                solution="Read header to recover seed, run LFSR forward, XOR.",
                files=["alpha.bin"],
            ),
            "beta": self._make_chal(
                "beta",
                rel="development/2013/CSAW-Quals/web/beta",
                name="beta",
                category="web",
                description="PHP cookie forging",
                solution="Forge admin cookie with leaked encryption key.",
                files=["index.php"],
            ),
        }
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        entries = load_corpus(self.tmp, idx_path)
        self.assertEqual(len(entries), 2)
        by_id = {e.challenge_id: e for e in entries}
        self.assertEqual(by_id["alpha"].category, "crypto")
        self.assertIn("LFSR forward", by_id["alpha"].solution_sketch)
        self.assertEqual(by_id["beta"].files, ["index.php"])
        self.assertIn("Forge admin cookie", by_id["beta"].solution_sketch)

    def test_loads_readme_description_hints_when_metadata_description_is_shorter(self):
        rel = "development/2013/CSAW-Quals/forensics/alpha"
        index = {
            "alpha": self._make_chal(
                "alpha",
                rel=rel,
                name="alpha",
                category="forensics",
                description="Short metadata description.",
                solution="",
                files=["capture.pcap"],
            )
        }
        chall_dir = self.tmp / rel
        (chall_dir / "README.md").write_text(
            "# alpha\n"
            "## Description\n"
            "Short metadata description.\n"
            "Hint: preserve this protocol clue from README.\n"
            "## Solution\n"
            "Use the protocol clue.\n",
            encoding="utf-8",
        )
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        entries = load_corpus(self.tmp, idx_path)

        self.assertIn("protocol clue", entries[0].description)

    def test_loads_companion_solver_file_into_solution_sketch(self):
        index = {
            "alpha": self._make_chal(
                "alpha",
                rel="development/2013/CSAW-Quals/crypto/alpha",
                name="alpha",
                category="crypto",
                description="solver is in a companion file",
                solution="`solve.py`",
                files=["cipher.bin"],
                extra_files={
                    "solve.py": "def recover_flag():\n    return 'method only, no literal flag'\n"
                },
            )
        }
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        entries = load_corpus(self.tmp, idx_path)

        self.assertEqual(len(entries), 1)
        self.assertIn("Companion solution file: solve.py", entries[0].solution_sketch)
        self.assertIn("def recover_flag", entries[0].solution_sketch)

    def test_loads_supporting_source_but_not_challenge_artifact(self):
        index = {
            "alpha": self._make_chal(
                "alpha",
                rel="development/2013/CSAW-Quals/rev/alpha",
                name="alpha",
                category="rev",
                description="binary with hidden source next to writeup",
                solution="Copy the algorithm from the bundled source.",
                files=["alpha.bin"],
                extra_files={
                    "alpha.bin": "not included as text even if readable",
                    "alpha.c": "uint32_t step(uint32_t x) { return x >> 1; }\n",
                },
            )
        }
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        entries = load_corpus(self.tmp, idx_path)

        self.assertIn("Companion solution file: alpha.c", entries[0].solution_sketch)
        self.assertIn("uint32_t step", entries[0].solution_sketch)
        self.assertNotIn("not included as text", entries[0].solution_sketch)

    def test_companion_source_drops_leading_license_banner(self):
        index = {
            "alpha": self._make_chal(
                "alpha",
                rel="development/2013/CSAW-Quals/rev/alpha",
                name="alpha",
                category="rev",
                description="source has a long banner",
                solution="Copy source.",
                files=["alpha.bin"],
                extra_files={
                    "alpha.c": "/* Copyright banner */\n\nuint32_t step(uint32_t x) { return x >> 1; }\n",
                },
            )
        }
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        entries = load_corpus(self.tmp, idx_path)

        self.assertNotIn("Copyright banner", entries[0].solution_sketch)
        self.assertIn("uint32_t step", entries[0].solution_sketch)

    def test_oracle_context_status_distinguishes_actionable_and_metadata_only(self):
        index = {
            "actionable": self._make_chal(
                "actionable",
                rel="development/2013/CSAW-Quals/rev/actionable",
                name="actionable",
                category="rev",
                description="binary with a solver",
                solution="Invert the transform and validate locally.",
                files=["actionable"],
            ),
            "metadata-only": self._make_chal(
                "metadata-only",
                rel="development/2013/CSAW-Quals/rev/metadata-only",
                name="metadata-only",
                category="rev",
                description="binary without a solver writeup",
                solution="",
                files=["metadata-only"],
            ),
        }
        idx_path = self.tmp / "development_dataset.json"
        idx_path.write_text(json.dumps(index), encoding="utf-8")

        self.assertEqual(
            oracle_context_status("actionable", dataset_root=str(self.tmp))["status"],
            "hit",
        )
        self.assertEqual(
            oracle_context_status("metadata-only", dataset_root=str(self.tmp))["status"],
            "metadata_only",
        )
        self.assertEqual(
            oracle_context_status("missing", dataset_root=str(self.tmp))["status"],
            "miss",
        )
        self.assertEqual(
            actionable_oracle_challenge_ids(dataset_root=str(self.tmp)),
            {"actionable"},
        )


class KnowledgeRetrieverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.entries = [
            _entry(
                "2013q-cry-csawpad",
                name="CSAWpad",
                category="crypto",
                description="Many-time-pad with 8 ciphertexts and one known plaintext key.",
                solution="Crib drag with 'the' across all 8 ciphertexts.",
                files=["csawpad.py"],
                event="CSAW-Quals",
            ),
            _entry(
                "2013f-cry-stfu",
                name="stfu",
                category="crypto",
                description="LFSR-based file encryption stored in a Secure Test File Unit.",
                solution="Read seed/tap/skip from header, run LFSR, XOR with body.",
                files=["stfu", "flag.stfu"],
                event="CSAW-Finals",
            ),
            _entry(
                "2013f-web-historypeats",
                name="historypeats",
                category="web",
                description="FuelPHP application; admin cookie can be forged.",
                solution="Extract encryption_key from PHP source, forge admin cookie.",
                files=["app/index.php"],
                event="CSAW-Finals",
            ),
            _entry(
                "2014q-pwn-ish",
                name="ish",
                category="pwn",
                description="Tiny shell-like program; format-string bug in printf.",
                solution="Use %n format string write to GOT entry.",
                files=["ish"],
                event="CSAW-Quals",
                year="2014",
            ),
        ]

    def test_category_prefilter_restricts_results(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "LFSR-based file encryption stored in a Secure Test File Unit. files: stfu, flag.stfu",
            category="crypto",
            top_k=4,
        )
        self.assertGreaterEqual(len(hits), 1)
        for hit in hits:
            self.assertEqual(hit.category, "crypto")

    def test_excludes_challenge_id(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "LFSR-based file encryption stored in a Secure Test File Unit.",
            category="crypto",
            top_k=4,
            exclude_challenge_ids=["2013f-cry-stfu"],
        )
        ids = {hit.challenge_id for hit in hits}
        self.assertNotIn("2013f-cry-stfu", ids)

    def test_direct_challenge_lookup_returns_corpus_hit(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )

        hit = retriever.hit_by_challenge_id("2013f-cry-stfu")

        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit.challenge_id, "2013f-cry-stfu")
        self.assertEqual(hit.score, 1.0)

    def test_direct_challenge_lookup_can_return_description_only_context(self):
        retriever = KnowledgeRetriever(
            [
                _entry(
                    "description-only",
                    name="description-only",
                    category="forensics",
                    description="Use the provided protocol hints and artifact names.",
                    solution="",
                    files=["capture.pcap"],
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )

        default_hit = retriever.hit_by_challenge_id("description-only")
        direct_hit = retriever.hit_by_challenge_id(
            "description-only",
            require_solution_sketch=False,
        )

        self.assertIsNone(default_hit)
        self.assertIsNotNone(direct_hit)
        assert direct_hit is not None
        self.assertEqual(
            direct_hit.description,
            "Use the provided protocol hints and artifact names.",
        )

    def test_excludes_event_pair(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "LFSR-based file encryption stored in a Secure Test File Unit.",
            category="crypto",
            top_k=4,
            exclude_event_keys=[("2013", "CSAW-Finals")],
        )
        for hit in hits:
            self.assertNotEqual((hit.year, hit.event), ("2013", "CSAW-Finals"))

    def test_unknown_category_falls_back_to_full_corpus(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "LFSR-based file encryption",
            category="totally_unknown_category",
            top_k=4,
        )
        self.assertGreaterEqual(len(hits), 1)

    def test_to_prompt_dict_truncates_long_solution(self):
        retriever = KnowledgeRetriever(
            self.entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "FuelPHP cookie forging",
            category="web",
            top_k=1,
        )
        self.assertEqual(len(hits), 1)
        rendered = hits[0].to_prompt_dict(max_solution_chars=10)
        self.assertLessEqual(len(rendered["solution_sketch"]), 10)

    def test_to_prompt_dict_redacts_literal_flags(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "flaggy",
                    name="flaggy",
                    category="crypto",
                    description="contains literal flag",
                    solution="The method recovers flag{do_not_copy_this}; then submit it.",
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("literal flag", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        self.assertNotIn("flag{do_not_copy_this}", rendered["solution_sketch"])
        self.assertIn("[REDACTED_FLAG]", rendered["solution_sketch"])

    def test_to_prompt_dict_redacts_flags_from_description(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "description-flaggy",
                    name="description-flaggy",
                    category="crypto",
                    description="The README description leaks flag{do_not_inject_this}.",
                    solution="Use the described method, not the answer literal.",
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("README description leaks", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        self.assertNotIn("flag{do_not_inject_this}", rendered["description"])
        self.assertIn("[REDACTED_FLAG]", rendered["description"])

    def test_to_prompt_dict_redacts_flags_from_file_names(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "file-flaggy",
                    name="file-flaggy",
                    category="crypto",
                    description="contains answer-like filename",
                    files=[
                        "solver.py",
                        "recover_flag.py",
                        "lower_case_answer_token.txt",
                        "flag{do_not_inject_file}.txt",
                        "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME.bin",
                    ],
                    solution="Use the filenames as artifacts, not answers.",
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("answer-like filename", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        files = rendered["files"]
        self.assertNotIn("flag{do_not_inject_file}.txt", files)
        self.assertNotIn("lower_case_answer_token.txt", files)
        self.assertNotIn("STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME.bin", files)
        self.assertIn("recover_flag.py", files)
        self.assertEqual(files.count("[REDACTED_FLAG].txt"), 2)
        self.assertIn("[REDACTED_FLAG].bin", files)

    def test_to_prompt_dict_redacts_bare_flag_tokens(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "bare-flaggy",
                    name="bare-flaggy",
                    category="crypto",
                    description="contains bare literal flag",
                    solution=(
                        "The final plaintext is "
                        "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME; derive it locally."
                    ),
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("bare literal", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        self.assertNotIn(
            "STFU_THIS_CHALLENGE_WAS_TOTALLY_NOT_LAME",
            rendered["solution_sketch"],
        )
        self.assertIn("[REDACTED_FLAG]", rendered["solution_sketch"])

    def test_to_prompt_dict_redacts_context_labeled_lowercase_bare_flags(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "lower-bare-flaggy",
                    name="lower-bare-flaggy",
                    category="crypto",
                    description="contains lowercase bare literal flag",
                    solution=(
                        "The final plaintext is "
                        "lower_case_answer_token; derive it locally."
                    ),
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("lowercase literal", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        self.assertNotIn("lower_case_answer_token", rendered["solution_sketch"])
        self.assertIn("[REDACTED_FLAG]", rendered["solution_sketch"])

    def test_to_prompt_dict_keeps_lowercase_method_tokens(self):
        hit = KnowledgeRetriever(
            [
                _entry(
                    "method-token",
                    name="method-token",
                    category="crypto",
                    description="contains method identifiers",
                    solution=(
                        "Use repeating-key XOR and implement recover_flag helper "
                        "against the ciphertext."
                    ),
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        ).retrieve("method identifiers", category="crypto", top_k=1)[0]

        rendered = hit.to_prompt_dict()
        self.assertIn("repeating-key", rendered["solution_sketch"])
        self.assertIn("recover_flag", rendered["solution_sketch"])

    def test_require_solution_sketch_filters_blank_entries(self):
        entries = [
            *self.entries,
            _entry(
                "2099-misc-empty",
                name="empty",
                category="crypto",
                description="placeholder",
                solution="",  # no solution sketch on purpose
                files=[],
            ),
        ]
        retriever = KnowledgeRetriever(
            entries,
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        hits = retriever.retrieve(
            "placeholder",
            category="crypto",
            top_k=10,
            require_solution_sketch=True,
        )
        self.assertNotIn("2099-misc-empty", {hit.challenge_id for hit in hits})

    def test_rag_mode_env_priority(self):
        with mock.patch.dict(
            os.environ,
            {
                "AUTOPENTEST_RAG_MODE": "strict",
                "AUTOPENTEST_RAG_DISABLED": "1",
                "AUTOPENTEST_RAG_STRICT_EXCLUDE": "",
            },
        ):
            self.assertEqual(rag_mode(), "strict")

        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "", "AUTOPENTEST_RAG_DISABLED": "1"}):
            self.assertEqual(rag_mode(), "disabled")

    def test_invalid_rag_mode_fails_fast(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "orcale"}):
            with self.assertRaisesRegex(ValueError, "unknown RAG mode 'orcale'"):
                rag_mode()

        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_DISABLED": "1"}):
            with self.assertRaisesRegex(ValueError, "unknown RAG mode 'filtered'"):
                rag_mode("filtered")

    def test_public_rag_payload_distinguishes_pending_from_disabled(self):
        self.assertEqual(
            public_rag_payload({"mode": "oracle"}),
            {
                "enabled": False,
                "status": "pending",
                "policy": "supplemental_context",
                "hint_count": 0,
            },
        )
        self.assertEqual(
            public_rag_payload({"mode": "strict"}),
            {
                "enabled": False,
                "status": "pending",
                "policy": "filtered_context",
                "hint_count": 0,
            },
        )
        self.assertEqual(
            public_rag_payload({"mode": "disabled"}),
            {
                "enabled": False,
                "status": "disabled",
                "policy": "disabled",
                "hint_count": 0,
            },
        )

    def test_public_rag_payload_normalizes_bad_counts(self):
        self.assertEqual(
            public_rag_payload(
                {
                    "mode": "oracle",
                    "enabled": True,
                    "status": "hit",
                    "hint_count": "bad",
                }
            ),
            {
                "enabled": True,
                "status": "hit",
                "policy": "supplemental_context",
                "hint_count": 0,
            },
        )


class CachedEmbeddingMatrixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_round_trip_uses_disk_cache(self):
        embedder = StubEmbedder()
        cache = CachedEmbeddingMatrix(embedder, cache_dir=self.tmp)
        texts = ["alpha doc", "beta doc", "gamma doc"]
        first = cache.encode_corpus(texts)
        second = cache.encode_corpus(texts)
        self.assertEqual(first.shape, second.shape)
        self.assertTrue((first == second).all())
        # Cache file should exist after the first call.
        cached_files = list(self.tmp.glob("*.npy"))
        self.assertEqual(len(cached_files), 1)

    def test_concurrent_writes_share_cache_path_without_tmp_collisions(self):
        embedder = StubEmbedder()
        texts = ["alpha doc", "beta doc", "gamma doc"]

        def encode_once():
            cache = CachedEmbeddingMatrix(embedder, cache_dir=self.tmp)
            return cache.encode_corpus(texts)

        with ThreadPoolExecutor(max_workers=8) as executor:
            matrices = list(executor.map(lambda _index: encode_once(), range(32)))

        first = matrices[0]
        self.assertTrue(all((matrix == first).all() for matrix in matrices))
        self.assertEqual(len(list(self.tmp.glob("*.npy"))), 1)
        self.assertEqual(list(self.tmp.glob(".*.tmp")), [])

    def test_cache_invalidates_on_content_change(self):
        embedder = StubEmbedder()
        cache = CachedEmbeddingMatrix(embedder, cache_dir=self.tmp)
        cache.encode_corpus(["alpha"])
        cache.encode_corpus(["alpha", "beta"])
        cached_files = list(self.tmp.glob("*.npy"))
        # Two distinct content hashes => two cache files.
        self.assertEqual(len(cached_files), 2)

    def test_corrupt_cache_read_logs_debug_context(self):
        embedder = StubEmbedder()
        cache = CachedEmbeddingMatrix(embedder, cache_dir=self.tmp)
        texts = ["alpha doc", "beta doc"]
        cache.encode_corpus(texts)
        cached_file = next(self.tmp.glob("*.npy"))
        cached_file.write_text("not a numpy matrix", encoding="utf-8")

        with self.assertLogs("killchain_docker.knowledge.embedder", level="DEBUG") as captured:
            matrix = cache.encode_corpus(texts)

        self.assertEqual(matrix.shape[0], len(texts))
        record = captured.records[0]
        self.assertEqual(record.cache_path, str(cached_file))
        self.assertEqual(record.model_id, embedder.model_id)
        self.assertIsNotNone(record.exc_info)


class _AugmenterFixture:
    """Small mixin that builds a stub-embedder retriever + augmenter."""

    @classmethod
    def build(cls, tmp: Path) -> tuple[KnowledgeRetriever, KnowledgeAugmenter, RunState]:
        entries = [
            _entry(
                "2013f-cry-stfu",
                name="stfu",
                category="crypto",
                description="LFSR-based file encryption with 16-byte header.",
                solution="Read seed/tap/skip from header, run LFSR, XOR.",
                files=["stfu", "flag.stfu"],
                event="CSAW-Finals",
            ),
            _entry(
                "2013q-cry-csawpad",
                name="CSAWpad",
                category="crypto",
                description="Many-time-pad with 8 ciphertexts.",
                solution="Crib drag with 'the' across all 8 ciphertexts.",
                files=["csawpad.py"],
                event="CSAW-Quals",
            ),
        ]
        retriever = KnowledgeRetriever(
            entries,
            embedder=StubEmbedder(),
            cache_dir=tmp,
        )
        state = RunState(
            objective="LFSR-based file encryption stored in a Secure Test File Unit.",
            authorized_scope=[],
            metadata={
                "challenge": {
                    "name": "stfu",
                    "category": "crypto",
                    "flag_format": "",
                    "files": ["stfu", "flag.stfu"],
                    "year": "2013",
                    "event": "CSAW-Finals",
                    "canonical_name": "2013f-cry-stfu",
                }
            },
        )
        return retriever, KnowledgeAugmenter(retriever), state


class _DirectLookupRetriever:
    """Retriever double whose dense result misses the current challenge."""

    def __len__(self) -> int:
        return 2

    def retrieve(self, *_args, **_kwargs) -> list[RetrievalHit]:
        return [
            RetrievalHit(
                challenge_id="distractor-challenge",
                name="distractor",
                category="crypto",
                year="2099",
                event="Future Quals",
                description="wrong context",
                solution_sketch="wrong method",
                files=["distractor.bin"],
                score=0.99,
            )
        ]

    def hit_by_challenge_id(self, challenge_id: str, **_kwargs) -> RetrievalHit | None:
        if challenge_id != "target-challenge":
            return None
        return RetrievalHit(
            challenge_id="target-challenge",
            name="target",
            category="crypto",
            year="2099",
            event="Future Quals",
            description="right context",
            solution_sketch="right method",
            files=["target.bin"],
            score=1.0,
        )


class KnowledgeAugmenterTests(unittest.TestCase):
    """The augmenter is the planner RAG integration point."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        env = mock.patch.dict(
            os.environ,
            {
                "AUTOPENTEST_RAG_MODE": "",
                "AUTOPENTEST_RAG_DISABLED": "",
                "AUTOPENTEST_RAG_STRICT_EXCLUDE": "",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.retriever, self.augmenter, self.state = _AugmenterFixture.build(self.tmp)

    def test_context_can_render_shaped_hits_for_retrieval_tests(self):
        context = self.augmenter.context_for(self.state)
        hits = context.prompt_hits(
            max_solution_chars=9000,
            max_description_chars=280,
            max_files=8,
        )
        self.assertGreaterEqual(len(hits), 1)
        first = hits[0]
        for required in ("rank", "category", "solution_sketch"):
            self.assertIn(required, first)
        self.assertNotIn("score", first)
        self.assertNotIn("challenge_id", first)
        self.assertNotIn("event", first)

    def test_context_for_caches_into_state_metadata(self):
        context = self.augmenter.context_for(self.state)
        score = context.top_score
        # Cosine is in [-1, 1].  We use the stub embedder here so the
        # absolute value / ordering isn't semantically meaningful, but
        # the cache shape / short-circuit invariants are.
        self.assertGreaterEqual(score, -1.0)
        self.assertLessEqual(score, 1.0)
        self.assertIn(
            context.top_challenge_id,
            {entry.challenge_id for entry in self.retriever.entries},
        )
        cached = self.state.metadata.get("rag")
        self.assertIsNotNone(cached)
        self.assertTrue(cached["enabled"])
        self.assertEqual(cached["mode"], "oracle")
        self.assertEqual(cached["status"], "hit")
        self.assertFalse(cached["strict_exclude"])
        rendered_hits = context.prompt_hits(
            max_solution_chars=9000,
            max_description_chars=280,
            max_files=8,
        )
        self.assertEqual(cached["hit_count"], len(rendered_hits))
        self.assertIn(
            cached["top_challenge_id"],
            {entry.challenge_id for entry in self.retriever.entries},
        )
        self.assertIn("hit_provenance", cached)
        self.assertNotIn("knowledge_hints", cached)
        self.assertGreaterEqual(cached["hint_count"], 1)
        self.assertEqual(cached["challenge_event_key"], "2013:csaw-finals")

    def test_context_for_logs_public_rag_status_only(self):
        with self.assertLogs("killchain_docker.knowledge.augmenter", level="INFO") as captured:
            self.augmenter.context_for(self.state)

        records = [
            record
            for record in captured.records
            if record.getMessage() == "RAG context resolved"
        ]
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertEqual(record.rag_mode, "oracle")
        self.assertTrue(record.rag_enabled)
        self.assertEqual(record.rag_status, "hit")
        self.assertEqual(record.rag_policy, "supplemental_context")
        self.assertEqual(record.hint_count, 1)
        self.assertEqual(record.retrieved_hit_count, 2)
        self.assertGreater(record.query_chars, 0)
        self.assertNotIn("knowledge_hints", record.__dict__)
        self.assertNotIn("hit_provenance", record.__dict__)
        self.assertNotIn("top_challenge_id", record.__dict__)

    def test_identity_match_limits_prompt_hints_to_matching_context(self):
        context = self.augmenter.context_for(self.state)

        self.assertEqual(
            [hit.challenge_id for hit in context.hits or []],
            ["2013f-cry-stfu"],
        )
        cached = self.state.metadata["rag"]
        self.assertEqual(cached["hit_count"], 1)
        self.assertEqual(cached["retrieved_hit_count"], 2)
        self.assertEqual(len(cached["hit_provenance"]), 2)
        self.assertEqual(cached["hint_count"], 1)

    def test_oracle_mode_adds_direct_context_when_dense_retrieval_misses_identity(self):
        retriever = _DirectLookupRetriever()
        state = RunState(
            objective="generic query whose dense result is a distractor",
            metadata={
                "challenge": {
                    "canonical_name": "target-challenge",
                    "category": "crypto",
                    "files": ["target.bin"],
                }
            },
        )

        augmenter = KnowledgeAugmenter(retriever, top_k=1, mode="oracle")  # type: ignore[arg-type]
        context = augmenter.context_for(state)

        self.assertEqual(
            [hit.challenge_id for hit in context.hits or []],
            ["target-challenge"],
        )
        cached = state.metadata["rag"]
        self.assertEqual(cached["retrieved_hit_count"], 1)
        self.assertEqual(
            [item["challenge_id"] for item in cached["hit_provenance"]],
            ["target-challenge", "distractor-challenge"],
        )
        self.assertEqual(cached["hint_count"], 1)
        self.assertNotIn("knowledge_hints", cached)

    def test_strict_mode_does_not_add_direct_context(self):
        retriever = _DirectLookupRetriever()
        state = RunState(
            objective="generic query whose dense result is a distractor",
            metadata={
                "challenge": {
                    "canonical_name": "target-challenge",
                    "category": "crypto",
                    "files": ["target.bin"],
                }
            },
        )

        augmenter = KnowledgeAugmenter(retriever, top_k=1, mode="strict")  # type: ignore[arg-type]
        context = augmenter.context_for(state)

        self.assertEqual(
            [hit.challenge_id for hit in context.hits or []],
            ["distractor-challenge"],
        )

    def test_description_only_identity_hint_is_not_actionable_oracle_context(self):
        late_hint = "late protocol hint survives description budget"
        description = "start " + ("filler " * 80) + late_hint
        retriever = KnowledgeRetriever(
            [
                _entry(
                    "description-only",
                    name="description-only",
                    category="forensics",
                    description=description,
                    solution="",
                    files=["capture.pcap"],
                )
            ],
            embedder=StubEmbedder(),
            cache_dir=self.tmp,
        )
        state = RunState(
            objective="recover file from capture",
            metadata={
                "challenge": {
                    "canonical_name": "description-only",
                    "category": "forensics",
                    "files": ["capture.pcap"],
                }
            },
        )

        augmenter = KnowledgeAugmenter(retriever, mode="oracle")
        context = augmenter.context_for(state)
        hints = context.prompt_hits(
            max_solution_chars=9000,
            max_description_chars=280,
            max_files=8,
        )
        cached = state.metadata["rag"]

        self.assertEqual(hints, [])
        self.assertEqual(context.status, "metadata_only")
        self.assertEqual(cached["status"], "metadata_only")
        self.assertEqual(cached["hit_count"], 0)
        self.assertEqual(cached["hint_count"], 0)
        self.assertNotIn("knowledge_hints", cached)

    def test_disabled_when_retriever_none(self):
        augmenter = KnowledgeAugmenter(retriever=None)
        self.assertFalse(augmenter.enabled)
        self.assertEqual(augmenter.for_planner(self.state), [])
        self.assertEqual(augmenter.context_for(self.state).top_score, 0.0)
        self.assertEqual(self.state.metadata["rag"]["status"], "unavailable")

    def test_disabled_mode_skips_even_configured_retriever(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "disabled"}):
            hits = self.augmenter.for_planner(self.state)
        self.assertEqual(hits, [])
        self.assertEqual(self.state.metadata["rag"]["mode"], "disabled")
        self.assertEqual(self.state.metadata["rag"]["status"], "disabled")

    def test_no_self_exclusion_by_default(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "", "AUTOPENTEST_RAG_STRICT_EXCLUDE": ""}):
            context = self.augmenter.context_for(self.state)
        ids = {hit.challenge_id for hit in context.hits or []}
        self.assertIn("2013f-cry-stfu", ids)

    def test_strict_exclude_env_filters_same_challenge(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_STRICT_EXCLUDE": "1"}):
            context = self.augmenter.context_for(self.state)
        ids = {hit.challenge_id for hit in context.hits or []}
        self.assertNotIn("2013f-cry-stfu", ids)
        self.assertNotIn("CSAW-Finals", {hit.event for hit in context.hits or []})
        self.assertEqual(self.state.metadata["rag"]["mode"], "strict")
        self.assertTrue(self.state.metadata["rag"]["strict_exclude"])

    def test_strict_mode_filters_same_challenge(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "strict"}):
            context = self.augmenter.context_for(self.state)
        ids = {hit.challenge_id for hit in context.hits or []}
        self.assertNotIn("2013f-cry-stfu", ids)

    def test_strict_mode_uses_event_key_when_year_event_fields_are_absent(self):
        self.state.metadata["challenge"].pop("year", None)
        self.state.metadata["challenge"].pop("event", None)
        self.state.metadata["challenge"]["event_key"] = "2013:csaw-finals"

        augmenter = KnowledgeAugmenter(self.retriever, mode="strict")
        context = augmenter.context_for(self.state)

        self.assertNotIn("2013f-cry-stfu", {hit.challenge_id for hit in context.hits or []})
        self.assertNotIn("CSAW-Finals", {hit.event for hit in context.hits or []})
        self.assertEqual(self.state.metadata["rag"]["excluded_event_keys"], ["2013:csaw-finals"])

    def test_explicit_mode_overrides_environment(self):
        augmenter = KnowledgeAugmenter(self.retriever, mode="strict")
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_MODE": "oracle"}):
            context = augmenter.context_for(self.state)
        self.assertNotIn("2013f-cry-stfu", {hit.challenge_id for hit in context.hits or []})
        self.assertEqual(self.state.metadata["rag"]["mode"], "strict")

    def test_cache_preserves_misleading_policy_annotation(self):
        self.state.metadata["rag"] = {
            "policy": "possibly_misleading",
            "stalled_families": ["lfsr"],
        }
        self.augmenter.for_planner(self.state)
        self.assertEqual(self.state.metadata["rag"]["policy"], "possibly_misleading")
        self.assertEqual(self.state.metadata["rag"]["stalled_families"], ["lfsr"])

    def test_challenge_metadata_carries_event_key_for_strict_rag(self):
        class FakeChallenge:
            canonical_name = "2013f-cry-stfu"
            name = "stfu"
            category = "crypto"
            year = "2013"
            event = "CSAW-Finals"
            flag_format = "flag{...}"
            flag = ""
            files = ["stfu", "flag.stfu"]
            server_name = ""
            port = None
            server_type = None
            server_description = None
            challenge = {}

        metadata = challenge_metadata(FakeChallenge())  # type: ignore[arg-type]

        self.assertEqual(metadata["year"], "2013")
        self.assertEqual(metadata["event"], "CSAW-Finals")
        self.assertEqual(metadata["event_key"], "2013:csaw-finals")


class PlannerInjectionTests(unittest.TestCase):
    """Sanity-check that PlanStrategy exposes only public RAG metadata."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        env = mock.patch.dict(
            os.environ,
            {
                "AUTOPENTEST_RAG_MODE": "",
                "AUTOPENTEST_RAG_DISABLED": "",
                "AUTOPENTEST_RAG_STRICT_EXCLUDE": "",
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.retriever, self.augmenter, self.state = _AugmenterFixture.build(self.tmp)

    def test_user_prompt_omits_raw_knowledge_hints(self):
        client = StaticLLMClient([{}])
        strategy = PlanStrategy(client, augmenter=self.augmenter)
        ctx = strategy.context_builder.build(self.state)
        prompt = strategy._render_prompt(ctx)
        payload = json.loads(prompt)
        self.assertIn("knowledge_augmentation", payload)
        self.assertNotIn("mode", payload["knowledge_augmentation"])
        self.assertNotIn("top_score", payload["knowledge_augmentation"])
        self.assertNotIn("strict_exclude", payload["knowledge_augmentation"])
        self.assertNotIn("challenge_identity_hit", payload["knowledge_augmentation"])
        self.assertNotIn("top_challenge_id", payload["knowledge_augmentation"])
        self.assertNotIn("hit_provenance", payload["knowledge_augmentation"])
        self.assertNotIn("related_writeups", payload)
        self.assertNotIn("knowledge_hints", payload)
        self.assertGreaterEqual(payload["knowledge_augmentation"]["hint_count"], 1)

    def test_disabled_augmenter_omits_knowledge_hints(self):
        client = StaticLLMClient([{}])
        strategy = PlanStrategy(client, augmenter=KnowledgeAugmenter(retriever=None))
        ctx = strategy.context_builder.build(self.state)
        payload = json.loads(strategy._render_prompt(ctx))
        self.assertNotIn("knowledge_hints", payload)


if __name__ == "__main__":
    unittest.main()
