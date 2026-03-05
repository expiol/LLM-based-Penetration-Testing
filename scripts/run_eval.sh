#!/usr/bin/env bash
set -euo pipefail

autopentest eval \
  --bench data/benchmarks/lab_benchmark.yaml \
  --config configs/eval.yaml \
  --i-understand-and-am-authorized
