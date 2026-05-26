from __future__ import annotations

import unittest

import run as run_entrypoint


class RunEntrypointTests(unittest.TestCase):
    def test_cli_single_challenge_overrides_run_config_run_all(self) -> None:
        args = run_entrypoint._args_from_config(
            [
                "--challenge",
                "demo-challenge",
                "--rag-mode",
                "enabled",
                "--max-cycles",
                "3",
                "--parallel-workers",
                "2",
                "--logdir",
                "logs/test",
                "--name",
                "smoke",
                "--no-debug",
            ]
        )

        self.assertEqual(args.challenge, "demo-challenge")
        self.assertFalse(args.run_all)
        self.assertEqual(args.rag_mode, "enabled")
        self.assertEqual(args.max_cycles, 3)
        self.assertEqual(args.parallel_workers, 2)
        self.assertEqual(args.logdir, "logs/test")
        self.assertEqual(args.name, "smoke")
        self.assertFalse(args.debug)

    def test_cli_subset_implies_run_all_batch_mode(self) -> None:
        args = run_entrypoint._args_from_config(
            [
                "--challenges",
                "alpha",
                "beta",
                "--rag-mode",
                "enabled",
            ]
        )

        self.assertEqual(args.challenges, ["alpha", "beta"])
        self.assertTrue(args.run_all)

    def test_cli_sample_options_are_forwarded(self) -> None:
        args = run_entrypoint._args_from_config(
            [
                "--run-all",
                "--rag-mode",
                "enabled",
                "--sample-size",
                "4",
                "--sample-seed",
                "11",
                "--sample-strategy",
                "category_round_robin",
            ]
        )

        self.assertTrue(args.run_all)
        self.assertEqual(args.sample_size, 4)
        self.assertEqual(args.sample_seed, 11)
        self.assertEqual(args.sample_strategy, "category_round_robin")


if __name__ == "__main__":
    unittest.main()
