#!/usr/bin/env bash
set -euo pipefail

docker compose -f docker/docker-compose.lab.yml up -d

echo "DVWA: http://127.0.0.1:8080"
echo "Juice Shop: http://127.0.0.1:3000"
