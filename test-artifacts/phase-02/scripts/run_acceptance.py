#!/usr/bin/env python3
"""Corrected read-after-write verifier for AEGIS Acceptance Pack 02."""
import json, os, sys, urllib.request, urllib.error
from pathlib import Path

BASE = os.getenv("AEGIS_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
MARKER = "AEGIS-ACCEPTANCE-PACK-02"

def request(method, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(
        BASE + path, data=body, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read().decode()
            return r.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try: detail = json.loads(raw)
        except Exception: detail = raw
        return e.code, detail

checks = []
def record(name, ok, detail):
    checks.append({"test": name, "passed": bool(ok), "detail": detail})
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")

status, health = request("GET", "/health/ready")
if status != 200 or health.get("status") != "ready":
    print("API not ready; no test data submitted.", file=sys.stderr)
    sys.exit(2)

source_name = f"{MARKER}-file-import"
status, source = request("POST", "/api/v1/sources", {
    "name": source_name, "source_type": "file_import",
    "domain": "cloud_saas", "config": {"test_run": MARKER}
})
if status != 201:
    print("Source registration failed; stopping:", status, source, file=sys.stderr)
    sys.exit(2)
source_id = source.get("id")
record("source_registration", bool(source_id), {"http_status": status, "source_id": source_id})

def do_import(label, fmt, content, mapping=None):
    payload = {"source_name": source_name, "domain": "cloud_saas", "format": fmt, "content": content}
    if mapping is not None:
        payload["mapping"] = mapping
    code, result = request("POST", "/api/v1/sources/import", payload)
    ok = code == 200 and result.get("validation") == "passed"
    record(label, ok, {"http_status": code, "input_count": result.get("input_count"),
                       "accepted": result.get("accepted"), "streaming": result.get("streaming"),
                       "error": result if code != 200 else None})
    if code == 200:
        record(label + "_counts",
               result.get("input_count") == result.get("accepted"),
               {"input_count": result.get("input_count"), "accepted": result.get("accepted")})
    return code, result

do_import("json_import", "json", (DATA / "events.json").read_text())
mapping = {
    "event_time": "timestamp", "event_type": "activity", "severity": "level",
    "src_ip": "source_address", "username": "actor", "host": "hostname",
    "message": "description"
}
do_import("jsonl_mapped_import", "jsonl", (DATA / "events.jsonl").read_text(), mapping)
do_import("csv_mapped_import", "csv", (DATA / "events.csv").read_text(), mapping)
do_import("syslog_import", "syslog", (DATA / "events.syslog").read_text())

# Correct verification: all 9 imported events use the dedicated source_name,
# including syslog records whose raw messages intentionally do not contain MARKER.
code, event_result = request("GET", "/api/v1/events?limit=500")
items = event_result.get("items", []) if code == 200 else []
source_events = [e for e in items if e.get("source") == source_name]
record("event_read_after_write", code == 200 and len(source_events) == 9,
       {"http_status": code, "events_for_test_source": len(source_events),
        "expected": 9, "event_types": [e.get("event_type") for e in source_events]})

code, alert_result = request("GET", "/api/v1/alerts?status=open&limit=500")
alerts = alert_result.get("items", []) if code == 200 else []
tagged_alerts = [a for a in alerts if MARKER in (a.get("message") or "")]
record("alert_read_after_write", code == 200 and len(tagged_alerts) >= 1,
       {"http_status": code, "tagged_open_alerts_visible": len(tagged_alerts)})

code, bad = request("POST", "/api/v1/sources/import", {
    "source_name": source_name, "domain": "cloud_saas", "format": "json",
    "content": '{"events": [not-valid-json]}'
})
record("malformed_json_rejected", code == 422, {"http_status": code, "response": bad})

code, bad = request("POST", "/api/v1/sources", {
    "name": f"{MARKER}-must-reject-secret", "source_type": "manual",
    "domain": "cloud_saas", "config": {"api_key": "must-not-be-stored"}
})
record("credential_config_rejected", code == 422, {"http_status": code, "response": bad})

report = {
    "marker": MARKER, "base_url": BASE,
    "passed": sum(x["passed"] for x in checks),
    "failed": sum(not x["passed"] for x in checks),
    "tests": checks,
    "cleanup": {
        "source_id": source_id, "source_name": source_name,
        "instructions": "Review the report, then run the existing cleanup_tagged_data.sh."
    }
}
out = ROOT / "results"
out.mkdir(exist_ok=True)
(out / "acceptance_report.json").write_text(json.dumps(report, indent=2))
print(f"\nRESULT: {report['passed']} passed, {report['failed']} failed")
print("Report:", out / "acceptance_report.json")
print("Test records were created. Review report, then clean up if desired.")
sys.exit(1 if report["failed"] else 0)
