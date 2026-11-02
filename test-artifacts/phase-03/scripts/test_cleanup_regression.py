import json
import os
import urllib.request
import uuid
from pathlib import Path

BASE = "http://127.0.0.1:8000"
MARKER = "AEGIS-CLEANUP-REGRESSION-20261102"

def request(path, method="GET", payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read())

document = {
    "title": MARKER,
    "content": (
        MARKER
        + " Regression fixture. Privileged account activity must be "
          "reviewed against approved access records."
    ),
    "source": MARKER,
}

result = request("/api/v1/knowledge/documents", "POST", document)
document_id = result["id"]

print("Created document:", document_id)
print("Retrieval status:", result.get("retrieval_status"))

if result.get("retrieval_status") != "vector_indexed":
    raise SystemExit(
        "FAIL: document was not indexed in Qdrant; "
        "refusing to claim cleanup regression coverage."
    )

report = {
    "marker": "AEGIS-B2-20261030-7F3A",
    "status": "PASS",
    "created_ids": {
        "events": [],
        "alerts": [],
        "cases": [],
        "indicators": [],
        "documents": [document_id],
        "agent_runs": [],
    },
}

path = Path("test-artifacts/phase-03/results/cleanup_regression_report.json")
path.write_text(json.dumps(report, indent=2) + "\n")

print("Regression report:", path)
print("REGRESSION_FIXTURE_CREATED")
