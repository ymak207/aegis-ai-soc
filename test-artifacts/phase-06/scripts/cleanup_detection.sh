#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../../.."
echo "Deletes only Phase 06 tagged events and cascaded alerts."
read -r -p "Type DELETE-PHASE-06 to continue: " confirm
[[ "$confirm" == "DELETE-PHASE-06" ]] || { echo "Cancelled."; exit 1; }
sudo docker compose exec -T postgres psql -U aegis -d aegis -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
WITH doomed AS (
 SELECT id FROM security_events
 WHERE source='phase06-detection' AND raw->>'phase06_run' LIKE 'P06%'
)
DELETE FROM security_events WHERE id IN (SELECT id FROM doomed);
COMMIT;
SELECT count(*) AS remaining_phase06_events FROM security_events
 WHERE source='phase06-detection' AND raw->>'phase06_run' LIKE 'P06%';
SELECT count(*) AS remaining_phase06_alerts FROM alerts a
 JOIN security_events e ON e.id=a.event_id
 WHERE e.source='phase06-detection' AND e.raw->>'phase06_run' LIKE 'P06%';
SQL
echo "Audit history intentionally retained."
