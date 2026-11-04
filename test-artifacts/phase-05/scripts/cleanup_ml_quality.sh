#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
REPORT="${REPORT:-test-artifacts/phase-05/results/ml_quality_report.json}"
[[ -f "$REPORT" ]] || { echo "Missing report; refusing cleanup."; exit 1; }

python3 - "$REPORT" <<'PY' >/tmp/aegis-phase05-cleanup.sql
import json, sys, uuid
r = json.load(open(sys.argv[1], encoding="utf-8"))
if r.get("marker") != "AEGIS-ML-QUALITY-20261103" or r.get("status") not in ("PASS", "FAIL", "IN_PROGRESS"):
    raise SystemExit("Marker/status mismatch; refusing cleanup.")
ids = r.get("created_ids", {})
for key in ("events", "ml_runs"):
    if not isinstance(ids.get(key, []), list):
        raise SystemExit(f"Invalid {key} list")
    for value in ids.get(key, []):
        try:
            uuid.UUID(value)
        except Exception:
            raise SystemExit(f"Invalid UUID in {key}: {value}")
for table, key in (("ml_runs", "ml_runs"), ("security_events", "events")):
    values = ",".join("'" + v + "'" for v in ids.get(key, []))
    if values:
        print(f"DELETE FROM {table} WHERE id IN ({values});")
PY

echo "This removes only Phase 05 event and ML-run IDs recorded in the report."
echo "Report status: $(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["status"])' "$REPORT")"
echo "Audit records are retained; event deletion cascades associated alerts."
read -r -p "Type DELETE-PHASE-05-ML-QUALITY to continue: " confirm
[[ "$confirm" == "DELETE-PHASE-05-ML-QUALITY" ]] || { echo "Cancelled."; exit 1; }
sudo docker compose exec -T postgres psql -U aegis -d aegis -v ON_ERROR_STOP=1 < /tmp/aegis-phase05-cleanup.sql
echo "Phase 05 ML quality test entities removed; audit records retained."
