#!/usr/bin/env bash
set -euo pipefail

docker compose -f docker/docker-compose.lab.yml down -v

echo "Lab stopped and volumes removed."
