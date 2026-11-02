#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
REPORT="test-artifacts/phase-03/results/b3_acceptance_report.json"
[[ -f "$REPORT" ]] || { echo "Missing B3 report; refusing cleanup."; exit 1; }
python3 - "$REPORT" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
if r.get("marker")!="AEGIS-B3-20261102": raise SystemExit("Marker mismatch; refusing cleanup.")
if r.get("status")!="PASS": raise SystemExit("B3 report is not PASS; review before cleanup.")
ids=r.get("created_ids",{}).get("events",[])
if len(ids)!=11: raise SystemExit(f"Expected exactly 11 B3 event IDs; found {len(ids)}")
print("B3 event IDs to delete:",len(ids))
print("Associated alerts will be removed by event foreign-key cascade.")
print("Audit rows will be retained.")
PY
read -r -p "Type DELETE-B3-TEST-DATA to continue: " confirm
[[ "$confirm" == "DELETE-B3-TEST-DATA" ]] || { echo "Cancelled."; exit 1; }
python3 - "$REPORT" <<'PY' > /tmp/aegis-b3-cleanup.sql
import json,sys
ids=json.load(open(sys.argv[1]))["created_ids"]["events"]
for eid in ids:
    if not isinstance(eid,str) or len(eid)!=36: raise SystemExit("Invalid event ID; refusing cleanup.")
print("DELETE FROM security_events WHERE id IN ("+",".join("'"+x+"'" for x in ids)+");")
PY
sudo docker compose exec -T postgres psql -U aegis -d aegis -v ON_ERROR_STOP=1 < /tmp/aegis-b3-cleanup.sql
echo "B3 events removed; associated alerts cascaded; audit rows retained."
