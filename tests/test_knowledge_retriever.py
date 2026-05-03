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
from pathlib import Path
from unittest import mock

from nyuctf_mutil_killchain.knowledge import KnowledgeAugmenter
from nyuctf_mutil_killchain.knowledge.corpus import (
    KnowledgeEntry,
    extract_solution_sketch,
    load_corpus,
)
from nyuctf_mutil_killchain.knowledge.embedder import (
    CachedEmbeddingMatrix,
    StubEmbedder,
)
from nyuctf_mutil_killchain.knowledge.retriever import KnowledgeRetriever
from nyuctf_mutil_killchain.llm import StaticLLMClient
from nyuctf_mutil_killchain.orchestrator.planning.strategy import PlanStrategy
from nyuctf_mutil_killchain.state import GlobalState


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

    def test_cache_invalidates_on_content_change(self):
        embedder = StubEmbedder()
        cache = CachedEmbeddingMatrix(embedder, cache_dir=self.tmp)
        cache.encode_corpus(["alpha"])
        cache.encode_corpus(["alpha", "beta"])
        cached_files = list(self.tmp.glob("*.npy"))
        # Two distinct content hashes => two cache files.
        self.assertEqual(len(cached_files), 2)


class _AugmenterFixture:
    """Small mixin that builds a stub-embedder retriever + augmenter."""

    @classmethod
    def build(cls, tmp: Path) -> tuple[KnowledgeRetriever, KnowledgeAugmenter, GlobalState]:
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
        state = GlobalState(
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


class KnowledgeAugmenterTests(unittest.TestCase):
    """The augmenter is the single integration point for planner + solver."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.retriever, self.augmenter, self.state = _AugmenterFixture.build(self.tmp)

    def test_for_planner_returns_shaped_hits(self):
        hits = self.augmenter.for_planner(self.state)
        self.assertGreaterEqual(len(hits), 1)
        first = hits[0]
        for required in ("challenge_id", "category", "solution_sketch", "score"):
            self.assertIn(required, first)

    def test_for_solver_uses_larger_solution_budget(self):
        # The solver budget is meant to be at least as generous as the
        # planner budget so the algorithm body fits.  We compare the two
        # budgets indirectly by reading the rendered ``solution_sketch``
        # length for the same hit.
        from nyuctf_mutil_killchain.knowledge.augmenter import (
            PLANNER_SOLUTION_CHARS,
            SOLVER_SOLUTION_CHARS,
        )
        self.assertGreater(SOLVER_SOLUTION_CHARS, PLANNER_SOLUTION_CHARS)
        # Build an entry with a long sketch that stresses both budgets.
        long_sketch = ("step. " * 800).strip()
        entries = [
            _entry(
                "long-sketch",
                name="longsketch",
                category="crypto",
                description="long sketch challenge",
                solution=long_sketch,
                files=["a"],
            )
        ]
        retriever = KnowledgeRetriever(
            entries, embedder=StubEmbedder(), cache_dir=self.tmp
        )
        augmenter = KnowledgeAugmenter(retriever)
        state = GlobalState(
            objective="long sketch",
            authorized_scope=[],
            metadata={"challenge": {"name": "longsketch", "category": "crypto"}},
        )
        planner_hits = augmenter.for_planner(state)
        solver_hits = augmenter.for_solver(state)
        self.assertGreaterEqual(len(planner_hits), 1)
        self.assertGreaterEqual(len(solver_hits), 1)
        self.assertGreater(
            len(solver_hits[0]["solution_sketch"]),
            len(planner_hits[0]["solution_sketch"]),
        )

    def test_top_score_caches_into_state_metadata(self):
        score = self.augmenter.top_score(self.state)
        # Cosine is in [-1, 1].  We use the stub embedder here so the
        # absolute value / ordering isn't semantically meaningful, but
        # the cache shape / short-circuit invariants are.
        self.assertGreaterEqual(score, -1.0)
        self.assertLessEqual(score, 1.0)
        cached = self.state.metadata.get("rag")
        self.assertIsNotNone(cached)
        self.assertEqual(cached["hit_count"], len(self.augmenter.for_planner(self.state)))
        self.assertIn(
            cached["top_challenge_id"],
            {entry.challenge_id for entry in self.retriever.entries},
        )
        # Calling top_score again must not re-run retrieval (cache short circuit).
        with mock.patch.object(
            self.retriever, "retrieve", side_effect=AssertionError("cache miss")
        ):
            second = self.augmenter.top_score(self.state)
        self.assertEqual(score, second)

    def test_disabled_when_retriever_none(self):
        augmenter = KnowledgeAugmenter(retriever=None)
        self.assertFalse(augmenter.enabled)
        self.assertEqual(augmenter.for_planner(self.state), [])
        self.assertEqual(augmenter.for_solver(self.state), [])
        self.assertEqual(augmenter.top_score(self.state), 0.0)

    def test_no_self_exclusion_by_default(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_STRICT_EXCLUDE": ""}):
            hits = self.augmenter.for_planner(self.state)
        ids = {hit["challenge_id"] for hit in hits}
        # The current challenge IS allowed to surface — chosen oracle setting.
        self.assertIn("2013f-cry-stfu", ids)

    def test_strict_exclude_env_filters_same_challenge(self):
        with mock.patch.dict(os.environ, {"AUTOPENTEST_RAG_STRICT_EXCLUDE": "1"}):
            hits = self.augmenter.for_planner(self.state)
        ids = {hit["challenge_id"] for hit in hits}
        self.assertNotIn("2013f-cry-stfu", ids)


class PlannerInjectionTests(unittest.TestCase):
    """Sanity-check that PlanStrategy renders ``related_writeups`` via the augmenter."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.retriever, self.augmenter, self.state = _AugmenterFixture.build(self.tmp)

    def test_user_prompt_includes_related_writeups(self):
        client = StaticLLMClient([{}])
        strategy = PlanStrategy(client, augmenter=self.augmenter)
        prompt = strategy._user_prompt(self.state)
        payload = json.loads(prompt)
        self.assertIn("related_writeups", payload)
        self.assertGreaterEqual(len(payload["related_writeups"]), 1)
        first = payload["related_writeups"][0]
        for required in ("challenge_id", "category", "solution_sketch", "score"):
            self.assertIn(required, first)

    def test_disabled_augmenter_omits_writeups(self):
        client = StaticLLMClient([{}])
        strategy = PlanStrategy(client, augmenter=KnowledgeAugmenter(retriever=None))
        payload = json.loads(strategy._user_prompt(self.state))
        self.assertNotIn("related_writeups", payload)


if __name__ == "__main__":
    unittest.main()
