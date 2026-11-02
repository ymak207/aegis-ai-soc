#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../../.."

REPORT="${REPORT:-test-artifacts/phase-03/results/acceptance_report.json}"

if [[ ! -f "$REPORT" ]]; then
    echo "Missing $REPORT; refusing cleanup."
    exit 1
fi

# Validate report and all IDs before any deletion.
DOC_IDS_JSON="$(python3 - "$REPORT" <<'PY'
import json
import sys
import uuid

report = json.load(open(sys.argv[1], encoding="utf-8"))

if report.get("marker") != "AEGIS-B2-20261030-7F3A":
    raise SystemExit("Marker mismatch; refusing cleanup.")

if report.get("status") != "PASS":
    raise SystemExit("Acceptance report is not PASS; refusing cleanup.")

ids = report.get("created_ids", {})

for key in ("events", "alerts", "cases", "indicators", "documents", "agent_runs"):
    values = ids.get(key, [])
    if not isinstance(values, list):
        raise SystemExit(f"Invalid ID list: {key}")
    for value in values:
        if not isinstance(value, str) or not value:
            raise SystemExit(f"Invalid ID in {key}")

documents = ids.get("documents", [])
for value in documents:
    try:
        uuid.UUID(value)
    except ValueError:
        raise SystemExit(f"Invalid document UUID: {value}")

print(json.dumps(documents))
PY
)"

echo "B2 report validated."
echo "Knowledge document IDs: $(python3 -c 'import json,sys; print(len(json.load(sys.stdin)))' <<< "$DOC_IDS_JSON")"
echo
echo "This removes ONLY IDs recorded by the B2 acceptance report."
echo "Qdrant document vectors are deleted and verified before PostgreSQL deletion."
echo "Audit log rows are intentionally preserved."

read -r -p "Type DELETE-B2-TEST-DATA to continue: " confirm
[[ "$confirm" == "DELETE-B2-TEST-DATA" ]] || {
    echo "Cancelled."
    exit 1
}

# Delete and verify document vectors using the API container's actual configuration.
# If Qdrant is unavailable or verification fails, stop before deleting PostgreSQL rows.
if [[ "$DOC_IDS_JSON" != "[]" ]]; then
    printf '%s' "$DOC_IDS_JSON" |
    sudo docker compose exec -T api python -c '
import json
import os
import sys
import urllib.request
import urllib.parse

ids = json.load(sys.stdin)
base = os.getenv("QDRANT_URL", "http://qdrant:6333").rstrip("/")
collection = urllib.parse.quote(
    os.getenv("QDRANT_COLLECTION", "aegis_knowledge"), safe=""
)
endpoint = f"{base}/collections/{collection}/points"

def request(path, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        path,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=15) as response:
        return json.loads(response.read())

print(f"Qdrant collection: {collection}")
print(f"Document vectors to delete: {len(ids)}")

result = request(
    endpoint + "/delete?wait=true",
    {"points": ids}
)

if result.get("status") != "ok":
    raise RuntimeError(f"Qdrant delete failed: {result}")

print("Qdrant deletion operation:", result.get("result"))

remaining = request(
    endpoint,
    {"ids": ids, "with_payload": False}
).get("result", [])

remaining_ids = [str(point.get("id")) for point in remaining]

if remaining_ids:
    raise RuntimeError(
        "Qdrant verification failed; points remain: "
        + ", ".join(remaining_ids)
    )

print("Qdrant verification PASS: all B2 document vectors absent.")
'
fi

# Only after Qdrant deletion succeeds, remove the corresponding DB records.
python3 - "$REPORT" <<'PY' > /tmp/aegis-b2-cleanup.sql
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
ids = report["created_ids"]

def vals(key):
    return ",".join(
        "'" + value.replace("'", "''") + "'"
        for value in ids.get(key, [])
    )

# Cases cascade to case_timeline; events cascade to alerts.
# Knowledge documents are deleted only after Qdrant verification.
for table, key in [
    ("cases", "cases"),
    ("knowledge_documents", "documents"),
    ("threat_indicators", "indicators"),
    ("agent_runs", "agent_runs"),
    ("security_events", "events"),
]:
    values = vals(key)
    if values:
        print(f"DELETE FROM {table} WHERE id IN ({values});")
PY

sudo docker compose exec -T postgres \
    psql -U aegis -d aegis -v ON_ERROR_STOP=1 \
    < /tmp/aegis-b2-cleanup.sql

echo
echo "B2 cleanup completed."
echo "Qdrant vectors verified absent; PostgreSQL test entities deleted."
echo "Audit rows retained."
