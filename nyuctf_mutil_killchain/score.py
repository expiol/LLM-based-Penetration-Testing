"""Score validation helpers for NYU multi-killchain benchmark runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from nyuctf.dataset import CTFDataset


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def challenge_names(split: str, dataset_path: str | None = None) -> list[str]:
    if dataset_path:
        dataset = CTFDataset(dataset_json=dataset_path)
    else:
        dataset = CTFDataset(split=split)
    return list(dataset.dataset.keys())


def summarize_logdir(logdir: Path) -> dict[str, dict[str, Any]]:
    results: dict[str, dict[str, Any]] = {}
    for path in sorted(logdir.glob("*.json")):
        payload = load_json(path)
        challenge = payload.get("challenge_metadata", {}).get("canonical_name") or path.stem
        results[challenge] = {
            "solved": bool(payload.get("solved")),
            "validated_flag": payload.get("state", {}).get("validated_flag")
            or payload.get("summary", {}).get("validated_flag"),
            "status": payload.get("status"),
            "finish_reason": payload.get("finish_reason"),
            "logfile": str(path),
        }
    return results


def summarize_run_dir(run_dir: Path) -> dict[str, dict[str, Any]]:
    jsonl_path = run_dir / "results.jsonl"
    if not jsonl_path.exists():
        raise FileNotFoundError(f"results.jsonl not found in {run_dir}")

    results: dict[str, dict[str, Any]] = {}
    for line in jsonl_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        challenge = row["challenge"]
        results[challenge] = {
            "solved": bool(row.get("solved")),
            "validated_flag": row.get("validated_flag"),
            "status": row.get("status"),
            "returncode": row.get("returncode"),
            "logfile": row.get("logfile"),
            "summary_file": row.get("summary_file"),
        }
    return results


def build_validation_payload(
    *,
    results: dict[str, dict[str, Any]],
    expected_challenges: list[str] | None,
    split: str,
) -> dict[str, Any]:
    bool_results = {challenge: bool(info.get("solved")) for challenge, info in sorted(results.items())}
    solved = sum(1 for solved_flag in bool_results.values() if solved_flag)
    total = len(bool_results)

    missing: list[str] = []
    unexpected: list[str] = []
    if expected_challenges is not None:
        expected_set = set(expected_challenges)
        observed_set = set(bool_results)
        missing = sorted(expected_set - observed_set)
        unexpected = sorted(observed_set - expected_set)

    return {
        "metadata": {
            "agent": "NYU Multi-Killchain",
            "split": split,
            "evaluated": total,
        },
        "score": {
            "solved": solved,
            "total": total,
            "solve_rate": round(solved / total, 4) if total else 0.0,
            "missing_count": len(missing),
            "unexpected_count": len(unexpected),
        },
        "coverage": {
            "missing": missing,
            "unexpected": unexpected,
        },
        "results": bool_results,
        "details": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate benchmark score for NYU multi-killchain logs")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--run-dir", help="Batch run directory containing results.jsonl")
    source.add_argument("--logdir", help="Directory of per-challenge JSON logs")
    parser.add_argument("--split", default="development", choices=["development", "test"])
    parser.add_argument("--dataset", help="Optional dataset JSON path")
    parser.add_argument("--output", help="Optional output JSON path")
    args = parser.parse_args()

    if args.run_dir:
        results = summarize_run_dir(Path(args.run_dir).expanduser().resolve())
        default_output = Path(args.run_dir).expanduser().resolve() / "score_validation.json"
    else:
        results = summarize_logdir(Path(args.logdir).expanduser().resolve())
        default_output = Path(args.logdir).expanduser().resolve() / "score_validation.json"

    expected = challenge_names(args.split, args.dataset)
    payload = build_validation_payload(results=results, expected_challenges=expected, split=args.split)

    output_path = Path(args.output).expanduser().resolve() if args.output else default_output
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    print(json.dumps(payload["score"], indent=2, ensure_ascii=True))
    print(f"wrote: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
