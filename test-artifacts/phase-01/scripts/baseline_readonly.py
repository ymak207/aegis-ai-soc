#!/usr/bin/env python3
"""Capture read-only AEGIS baseline endpoints; no POST/PATCH requests."""
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
OUT = Path("test-artifacts/phase-01/results")
OUT.mkdir(parents=True, exist_ok=True)
PATHS = [
    "/health/ready", "/api/v1/overview", "/api/v1/lab/scenarios",
    "/api/v1/lab/runs", "/api/v1/sources", "/api/v1/events",
    "/api/v1/alerts", "/api/v1/correlations", "/api/v1/evaluations/results",
    "/api/v1/ml/anomaly/runs", "/api/v1/integrations", "/api/v1/data/quality",
    "/api/v1/platform/catalog", "/api/v1/platform/studio",
    "/api/v1/graph/summary", "/api/v1/mcp/tools", "/api/v1/audit",
]
results = {
    "captured_at": datetime.now(timezone.utc).isoformat(),
    "base_url": BASE, "mutating_requests_sent": 0, "results": []
}
for path in PATHS:
    req = Request(BASE + path, method="GET", headers={"Accept": "application/json"})
    try:
        with urlopen(req, timeout=20) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                body = json.loads(raw)
            except json.JSONDecodeError:
                body = raw
            results["results"].append({"path": path, "status": response.status, "body": body})
            print(f"[{response.status}] {path}")
    except HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        results["results"].append({"path": path, "status": exc.code, "body": raw})
        print(f"[{exc.code}] {path}")
    except (URLError, TimeoutError) as exc:
        results["results"].append({"path": path, "error": str(exc)})
        print(f"[ERROR] {path}: {exc}")

(OUT / "baseline_get_results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
print("\\nSaved:", OUT / "baseline_get_results.json")
print("Mutating requests sent: 0")
