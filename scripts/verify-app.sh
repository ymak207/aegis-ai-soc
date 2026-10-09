#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
echo "== Validate Compose configuration =="
sudo docker compose config -q
echo "== Build and start core services =="
sudo docker compose up -d --build
echo "== Wait for API readiness =="
ready=0
for attempt in $(seq 1 40); do
  if curl --fail --silent http://127.0.0.1:8000/health/ready >/tmp/aegis-ready.json; then ready=1; break; fi
  sleep 3
done
if [[ "$ready" != 1 ]]; then echo "API readiness timed out; recent logs:" >&2; sudo docker compose logs --tail=100 api postgres redis >&2; exit 1; fi
cat /tmp/aegis-ready.json >&2
curl --fail --silent http://127.0.0.1:8000/api/v1 >&2
echo
curl --fail --silent http://127.0.0.1:5173/ | head -c 300 >&2
echo
sudo docker compose exec -T api python -m pytest -q /app/tests
echo "APPLICATION VERIFICATION PASSED" >&2
