#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
echo "== Validate Compose configuration =="
sudo docker compose config -q
echo "== Start AEGIS AI SOC core services =="
sudo docker compose up -d --build
"$(dirname "$0")/status.sh" --wait
