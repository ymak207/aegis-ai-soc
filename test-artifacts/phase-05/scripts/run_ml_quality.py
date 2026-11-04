#!/usr/bin/env python3
"""Phase 05: ML ranking diagnostics, sparse-field robustness, scaling and concurrency."""
import concurrent.futures
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = ROOT / "data/ml_quality_events.json"
RESULTS = ROOT / "results"
REPORT_PATH = RESULTS / "ml_quality_report.json"
BASE = "http://127.0.0.1:8000"
MARKER = "AEGIS-ML-QUALITY-20261103"
checks, event_ids, run_ids, run_results = [], [], [], []
label_by_event_id = {}
fixture = json.loads(FIXTURE_PATH.read_text())


def save_report(status="IN_PROGRESS"):
    report = {
        "marker": MARKER,
        "dataset_version": fixture.get("dataset_version"),
        "status": status,
        "checks": checks,
        "created_ids": {"events": event_ids, "ml_runs": run_ids},
        "label_counts": fixture.get("counts"),
        "label_by_event_id": label_by_event_id,
        "runs": run_results,
        "interpretation": [
            "Precision@K and recall@K are ranking diagnostics computed only over the API's returned top-25 list.",
            "The API does not return scores for every event, so full-dataset ROC-AUC, PR-AUC, calibration, and threshold optimization are not measurable in this phase.",
            "The fixture is synthetic and deliberately separates rare-event patterns from routine activity; results are not evidence of production detection efficacy.",
            "benign_sparse cases represent legitimate telemetry with missing src_ip, username, and host; their ranking indicates sensitivity to missingness, not confirmed false-positive rates in real environments."
        ]
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2, default=str) + "\n")


def request(path, method="GET", payload=None, timeout=180):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path, data=body,
        headers={"Content-Type": "application/json"},
        method=method
    )
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            raw = response.read()
            data = json.loads(raw) if raw else {}
            return response.status, data, round((time.perf_counter() - started) * 1000)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            data = json.loads(raw)
        except Exception:
            data = {"raw": raw}
        return exc.code, data, round((time.perf_counter() - started) * 1000)


def check(name, condition, details=None):
    checks.append({
        "name": name,
        "status": "PASS" if condition else "FAIL",
        "details": details or {}
    })
    print(("PASS" if condition else "FAIL") + ": " + name)
    save_report()
    if not condition:
        raise AssertionError(f"{name}: {details}")


def run_model(limit, label):
    status, result, elapsed_ms = request(
        f"/api/v1/ml/anomaly/run?limit={limit}", "POST"
    )
    run_id = result.get("run_id")
    if run_id and run_id not in run_ids:
        run_ids.append(run_id)
    scored = result.get("top_anomalies", [])
    scored_ids = [x.get("event_id") for x in scored]
    ranked_labels = [label_by_event_id.get(eid, "unmapped") for eid in scored_ids]
    counts = Counter(ranked_labels)
    k = len(ranked_labels)
    selected_ids = event_ids[-limit:]
    positive_total = sum(1 for eid in selected_ids if label_by_event_id.get(eid) == "synthetic_outlier")
    positives_in_top = counts.get("synthetic_outlier", 0)
    precision_at_k = round(positives_in_top / k, 4) if k else None
    recall_at_k = round(positives_in_top / positive_total, 4) if positive_total else None
    details = {
        "run_id": run_id,
        "limit": limit,
        "http_status": status,
        "elapsed_ms": elapsed_ms,
        "sample_count": result.get("sample_count"),
        "feature_count": result.get("feature_count"),
        "top_k_returned": k,
        "anomaly_candidate_count": result.get("anomaly_candidate_count"),
        "top_k_label_counts": dict(counts),
        "synthetic_outliers_in_top_k": positives_in_top,
        "precision_at_k": precision_at_k,
        "recall_at_k": recall_at_k,
        "ranked_event_ids": scored_ids,
        "ranked_labels": ranked_labels
    }
    run_results.append(details)
    save_report()
    return status, result, details


def validate_run(label, status, result, details, expected):
    contract = (
        status == 200
        and result.get("model_name") == "IsolationForest"
        and result.get("model_version") == "aegis-iforest-v1"
        and result.get("training_mode") == "unsupervised-on-recent-stored-events"
    )
    check(f"{label}_model_contract", contract, {
        "http_status": status,
        "model_name": result.get("model_name"),
        "model_version": result.get("model_version"),
        "training_mode": result.get("training_mode")
    })
    sample_ok = (
        result.get("sample_count") == expected
        and result.get("feature_count", 0) > 0
        and 0 < len(result.get("top_anomalies", [])) <= 25
        and len(set(details["ranked_event_ids"])) == len(details["ranked_event_ids"])
        and all(x in label_by_event_id for x in details["ranked_event_ids"])
    )
    check(f"{label}_sample_and_rank_contract", sample_ok, {
        "expected_sample_count": expected,
        "actual_sample_count": result.get("sample_count"),
        "top_k_returned": details["top_k_returned"],
        "all_ranked_events_scoped": all(x in label_by_event_id for x in details["ranked_event_ids"])
    })
    # Metrics are reported, not gated on arbitrary thresholds in this exploratory phase.
    print(f"INFO: {label} top-{details['top_k_returned']} precision={details['precision_at_k']} "
          f"recall={details['recall_at_k']} labels={details['top_k_label_counts']}")


try:
    records = fixture["events"]
    check("fixture_integrity", fixture.get("marker") == MARKER
          and fixture.get("dataset_version") == "aegis-ml-quality-v1"
          and len(records) == 500
          and fixture.get("counts") == {
              "total": 500, "routine": 400, "benign_sparse": 50, "synthetic_outlier": 50
          }, {"dataset_version": fixture.get("dataset_version"), "records": len(records),
              "counts": fixture.get("counts")})

    # Validate minimum sample behavior without creating any data.
    status, invalid, _ = request("/api/v1/ml/anomaly/run?limit=19", "POST")
    check("reject_limit_below_20", status == 422, {"http_status": status, "response": invalid})

    # Give all events current timestamps while preserving order. API reads newest N.
    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload = []
    for index, item in enumerate(records):
        event = {k: v for k, v in item.items() if k not in ("case", "label")}
        event["event_time"] = (now + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")
        event["raw"] = {
            "phase05_marker": MARKER,
            "fixture_case": item["case"],
            "ground_truth_label": item["label"],
            "fixture_index": index
        }
        payload.append(event)

    status, ingestion, _ = request("/api/v1/events/batch", "POST", {"events": payload})
    items = ingestion.get("items", [])
    event_ids.extend(x.get("event_id") for x in items if x.get("event_id"))
    for item, response_item in zip(records, items):
        eid = response_item.get("event_id")
        if eid:
            label_by_event_id[eid] = item["label"]
    check("ingest_500_labeled_events", status == 200 and ingestion.get("accepted") == 500
          and len(event_ids) == 500 and len(items) == 500,
          {"http_status": status, "accepted": ingestion.get("accepted"),
           "returned_ids": len(event_ids)})
    check("no_duplicate_ingestion", all(not x.get("duplicate", False) for x in items),
          {"duplicate_count": sum(bool(x.get("duplicate")) for x in items)})

    for limit in (20, 120, 500):
        status, result, details = run_model(limit, f"scale_{limit}")
        validate_run(f"scale_{limit}", status, result, details, limit)

    # Two simultaneous requests on the same stable 500-event population.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(request, "/api/v1/ml/anomaly/run?limit=500", "POST")
                   for _ in range(2)]
        concurrent_results = [f.result() for f in futures]
    concurrent_ids = []
    concurrent_ok = True
    for status, result, elapsed_ms in concurrent_results:
        rid = result.get("run_id")
        if rid:
            run_ids.append(rid)
            concurrent_ids.append(rid)
        concurrent_ok = concurrent_ok and (
            status == 200 and result.get("sample_count") == 500
            and result.get("model_name") == "IsolationForest"
        )
        run_results.append({
            "run_id": rid, "scenario": "concurrent_500",
            "http_status": status, "elapsed_ms": elapsed_ms,
            "sample_count": result.get("sample_count"),
            "anomaly_candidate_count": result.get("anomaly_candidate_count")
        })
    save_report()
    check("concurrent_runs_complete_and_unique", concurrent_ok
          and len(concurrent_ids) == 2 and len(set(concurrent_ids)) == 2,
          {"run_ids": concurrent_ids, "statuses": [x[0] for x in concurrent_results],
           "elapsed_ms": [x[2] for x in concurrent_results]})

    # Persistence and audit checks for every run created by this phase.
    status, history, _ = request("/api/v1/ml/anomaly/runs?limit=100")
    found = [x for x in history.get("items", []) if x.get("id") in run_ids]
    check("all_five_runs_persisted", status == 200 and len(set(x.get("id") for x in found)) == 5,
          {"http_status": status, "expected_run_count": 5,
           "persisted_run_count": len(set(x.get("id") for x in found))})
    status, audit, _ = request("/api/v1/audit?limit=500")
    audited = [x for x in audit.get("items", [])
               if x.get("action") == "ml.anomaly_run" and x.get("entity_id") in run_ids]
    check("all_five_runs_audited", status == 200 and len(set(x.get("entity_id") for x in audited)) == 5,
          {"http_status": status, "expected_audit_count": 5,
           "audit_count": len(set(x.get("entity_id") for x in audited))})

    save_report("PASS")
    print("\nReport:", REPORT_PATH)
    print("Status: PASS")
    print("Checks:", sum(x["status"] == "PASS" for x in checks), "/", len(checks))
except Exception as exc:
    save_report("FAIL")
    print("\nAcceptance stopped:", type(exc).__name__, str(exc))
    print("Partial report saved for scoped cleanup:", REPORT_PATH)
    raise
