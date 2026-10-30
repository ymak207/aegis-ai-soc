#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
MARKER="AEGIS-ACCEPTANCE-PACK-02"
echo "This deletes only records whose source/message/raw test marker matches:"
echo "$MARKER"
read -r -p "Type DELETE-TEST-DATA to continue: " CONFIRM
if [[ "$CONFIRM" != "DELETE-TEST-DATA" ]]; then
  echo "Cancelled; no records deleted."
  exit 0
fi
sudo docker compose exec -T api python - <<'PY'
import os
import psycopg
from psycopg.types.json import Jsonb

marker = "AEGIS-ACCEPTANCE-PACK-02"
conn = psycopg.connect(
    host=os.getenv("DB_HOST", "postgres"),
    port=int(os.getenv("DB_PORT", "5432")),
    dbname=os.getenv("DB_NAME", "aegis"),
    user=os.getenv("DB_USER", "aegis"),
    password=os.getenv("DB_PASSWORD", "local-dev-change-me"),
)
try:
    with conn:
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM security_events
                WHERE source = %s OR message LIKE %s OR raw->>'test_run' = %s
            """, (f"{marker}-file-import", f"%{marker}%", marker))
            events = cur.rowcount
            cur.execute("""
                DELETE FROM sources
                WHERE name = %s
            """, (f"{marker}-file-import",))
            sources = cur.rowcount
    print(f"Deleted tagged events (alerts cascade): {events}")
    print(f"Deleted dedicated test sources: {sources}")
finally:
    conn.close()
PY
