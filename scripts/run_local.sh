#!/usr/bin/env bash
set -euo pipefail

autopentest run \
  --target data/targets/dvwa_local.yaml \
  --config configs/dev.yaml \
  --i-understand-and-am-authorized
