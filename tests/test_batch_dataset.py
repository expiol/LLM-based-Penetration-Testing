from __future__ import annotations

import argparse
import unittest
from pathlib import Path
from types import SimpleNamespace
from killchain_docker.batch.dataset import (
    derive_objective,
    _scorable_expected_flag,
    sample_challenge_names,
)


class _Dataset:
    basedir = Path("/tmp/demo-dataset")

    _categories = {
        "alpha": "crypto",
        "beta": "web",
        "gamma": "crypto",
        "delta": "pwn",
        "placeholder": "crypto",
    }
    _flags = {
        "alpha": "flag{alpha}",
        "beta": "flag{beta}",
        "gamma": "flag{gamma}",
        "delta": "plain_bare_flag",
        "placeholder": "flag{xxxxxxxxxxxxxx}",
    }

    def get(self, name: str) -> dict[str, str]:
        return {"category": self._categories[name], "flag": self._flags[name]}


class BatchDatasetTests(unittest.TestCase):
    def test_random_sample_is_seeded(self) -> None:
        args = argparse.Namespace(
            rag_mode="strict",
            sample_size=2,
            sample_seed=7,
            sample_strategy="random",
        )

        self.assertEqual(
            sample_challenge_names(
                _Dataset(),
                args,
                ["alpha", "beta", "gamma", "delta"],
            ),
            ["delta", "beta"],
        )

    def test_category_round_robin_sample_spreads_categories(self) -> None:
        args = argparse.Namespace(
            rag_mode="strict",
            sample_size=3,
            sample_seed=0,
            sample_strategy="category_round_robin",
        )

        self.assertEqual(
            sample_challenge_names(
                _Dataset(),
                args,
                ["alpha", "beta", "gamma", "delta"],
            ),
            ["gamma", "delta", "beta"],
        )

    def test_enabled_sample_uses_original_candidate_pool(self) -> None:
        args = argparse.Namespace(
            rag_mode="enabled",
            split="development",
            category=None,
            sample_size=2,
            sample_seed=0,
            sample_strategy="random",
        )

        self.assertEqual(
            sample_challenge_names(_Dataset(), args, ["alpha", "beta", "gamma"]),
            ["alpha", "gamma"],
        )

    def test_full_selection_keeps_all_entries(
        self,
    ) -> None:
        args = argparse.Namespace(
            rag_mode="enabled",
            split="development",
            category=None,
            sample_size=None,
            sample_seed=0,
            sample_strategy="random",
        )

        self.assertEqual(
            sample_challenge_names(_Dataset(), args, ["alpha", "beta", "gamma"]),
            ["alpha", "beta", "gamma"],
        )

    def test_placeholder_expected_flags_are_not_scorable(self) -> None:
        self.assertFalse(_scorable_expected_flag("flag{xxxxxxxxxxxxxx}"))
        self.assertFalse(_scorable_expected_flag("flag{...}"))
        self.assertTrue(_scorable_expected_flag("flag{real_value}"))
        self.assertTrue(_scorable_expected_flag("BARE_FLAG_VALUE"))

    def test_sample_size_larger_than_pool_fails(self) -> None:
        args = argparse.Namespace(
            rag_mode="strict",
            sample_size=3,
            sample_seed=0,
            sample_strategy="random",
        )

        with self.assertRaisesRegex(ValueError, "exceeds available challenges"):
            sample_challenge_names(_Dataset(), args, ["alpha", "beta"])

    def test_derived_objective_omits_category_operational_checklists(self) -> None:
        challenge = SimpleNamespace(
            name="demo",
            category="forensics",
            description="recover the hidden token",
            files=["artifact.img"],
        )

        objective = derive_objective(challenge, [])

        self.assertIn("Solve the NYU CTF challenge 'demo'", objective)
        self.assertIn("/home/ctfplayer/ctf_files", objective)
        for disallowed in (
            "Inspect file formats",
            "extract embedded files",
            "packet captures",
            "hidden partitions",
            "deleted files",
            "git repositories",
            "Identify the cipher",
            "known-plaintext attacks",
        ):
            self.assertNotIn(disallowed, objective)


if __name__ == "__main__":
    unittest.main()
