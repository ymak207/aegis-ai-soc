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
curl --noproxy '*' --fail --silent --show-error --output /dev/null --write-out 'Frontend HTTP %{http_code}\n' http://127.0.0.1:5173/ >&2
echo
sudo docker compose exec -T api python -m pytest -q /app/tests
echo "== Verify Lab catalog and end-to-end synthetic suite =="
curl --fail --silent --show-error http://127.0.0.1:8000/api/v1/lab/scenarios >/tmp/aegis-lab-catalog.json
python3 - <<'PYVERIFY'
import json
p=json.load(open('/tmp/aegis-lab-catalog.json'))
expected={'ecommerce','telecom','logistics','cloud_saas','financial_services'}
assert set(p['domains']) == expected, p.get('domains')
assert p['scenario_count'] >= 30, p['scenario_count']
print(f"Lab catalog OK: {p['scenario_count']} scenarios across {len(p['domains'])} domains")
PYVERIFY
curl --fail --silent --show-error -H 'Content-Type: application/json' -d '{"domain":"all","scenario":"mixed_suite","scale":1}' http://127.0.0.1:8000/api/v1/lab/run >/tmp/aegis-lab-run.json
python3 - <<'PYVERIFY'
import json,sys
p=json.load(open('/tmp/aegis-lab-run.json'))
print(f"Lab run {p.get('run_id')}: {p.get('passed')}/{p.get('result_count')} passed; failures={p.get('failed')}")
if not p.get('result_count') or p.get('failed') != 0: sys.exit('Lab assertions failed')
PYVERIFY
echo "== Verify local ML anomaly baseline =="
curl --fail --silent --show-error -X POST 'http://127.0.0.1:8000/api/v1/ml/anomaly/run?limit=1000' >/tmp/aegis-ml-run.json
python3 - <<'PYVERIFY'
import json,sys
p=json.load(open('/tmp/aegis-ml-run.json'))
print(f"ML run {p.get('run_id')}: model={p.get('model_name')} samples={p.get('sample_count')} candidates={p.get('anomaly_candidate_count')}")
if p.get('model_version') != 'aegis-iforest-v1' or p.get('sample_count',0) < 20: sys.exit('ML baseline output invalid')
PYVERIFY
echo "== Verify frontend TypeScript and production build =="
sudo docker compose exec -T frontend npm test
sudo docker compose exec -T frontend npm run build
echo "APPLICATION VERIFICATION PASSED" >&2
