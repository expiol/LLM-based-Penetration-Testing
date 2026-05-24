#!/usr/bin/env bash
set -Eeuo pipefail

network_name="${AUTOPENTEST_DOCKER_NETWORK:-ctfnet}"
conda_env="${AUTOPENTEST_CONDA_ENV:-autopentest}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() {
    printf '%s\n' "$*" >&2
}

if docker network inspect "$network_name" >/dev/null 2>&1; then
    log "Docker network exists: ${network_name}"
else
    log "Creating Docker network: ${network_name}"
    docker network create "$network_name"
fi

log "Building Docker image: ctfenv:latest"
docker build \
    --platform linux/amd64 \
    --build-arg HOST_UID="$(id -u)" \
    -t ctfenv:latest \
    -f "$repo_root/Dockerfile" \
    "$repo_root"

log "Installing Python package in conda env: ${conda_env}"
conda run -n "$conda_env" python -m pip install --editable "$repo_root"
