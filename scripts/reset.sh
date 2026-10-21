#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" != "--yes" ]]; then
  echo "WARNING: This destroys all Compose-managed persistent volumes for AEGIS, including PostgreSQL records, Redis data, and optional profile data."
  echo "It does not delete your source code or .env file."
  read -r -p 'Type RESET-AEGIS to continue: ' confirmation
  [[ "$confirmation" == "RESET-AEGIS" ]] || { echo "Reset cancelled."; exit 1; }
fi
echo "Stopping services and deleting Compose volumes..."
sudo docker compose down --volumes --remove-orphans
echo "Reset complete. Source code and .env were preserved. To start with a clean database run: ./scripts/start.sh"
