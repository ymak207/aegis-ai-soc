#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")/.."
WAIT=0
[[ "${1:-}" == "--wait" ]] && WAIT=1
sudo docker compose ps
if [[ "$WAIT" == 1 ]]; then
  echo "== Waiting for API readiness =="
  ready=0
  for attempt in $(seq 1 40); do
    if curl --noproxy '*' --fail --silent http://127.0.0.1:8000/health/ready >/tmp/aegis-ready.json; then ready=1; break; fi
    sleep 3
  done
  if [[ "$ready" != 1 ]]; then echo "API readiness failed; recent logs follow." >&2; sudo docker compose logs --tail=80 api postgres redis >&2; exit 1; fi
  cat /tmp/aegis-ready.json; echo
  curl --noproxy '*' --fail --silent --show-error --output /dev/null --write-out 'Frontend HTTP %{http_code}\n' http://127.0.0.1:5173/
fi
