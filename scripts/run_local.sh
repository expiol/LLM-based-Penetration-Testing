#!/usr/bin/env bash
set -euo pipefail

autopentest run --target data/targets/sample_target.yaml --scope data/targets/sample_scope.yaml
