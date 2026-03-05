#!/usr/bin/env bash
set -euo pipefail

autopentest eval --benchmark data/benchmarks/sample_benchmark.yaml --scope data/targets/sample_scope.yaml
