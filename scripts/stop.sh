#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
echo "Stopping AEGIS services; persistent volumes are preserved."
sudo docker compose stop
