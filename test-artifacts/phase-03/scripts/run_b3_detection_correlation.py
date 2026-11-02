#!/usr/bin/env python3
"""B3 detection/correlation API acceptance; no external dependencies."""
import json, os, sys, time, urllib.request, urllib.error
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DATA=ROOT/"data"/"detection_correlation_events.json"
OUT=ROOT/"results"/"b3_acceptance_report.json"
BASE=os.environ.get("AEGIS_BASE_URL","http://127.0.0.1:8000").rstrip("/")
checks=[]
created={"events":[],"alerts":[]}
def request(method,path,payload=None,expected=(200,)):
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(BASE+path,data=data,method=method,
        headers={"Content-Type":"application/json"} if data is not None else {})
    try:
        with urllib.request.urlopen(req,timeout=45) as r: status=r.status; raw=r.read().decode()
    except urllib.error.HTTPError as e: status=e.code; raw=e.read().decode()
    try: body=json.loads(raw) if raw else {}
    except Exception: body={"raw":raw}
    if status not in expected: raise AssertionError(f"{method} {path}: HTTP {status}, expected {expected}; {body}")
    return body
def passed(name,detail):
    checks.append({"name":name,"status":"PASS","detail":detail})
    print(f"PASS {name}: {detail}")
def main():
    ds=json.loads(DATA.read_text())
    marker=ds["marker"]
    ready=request("GET","/health/ready")
    assert ready.get("status")=="ready" and ready.get("checks",{}).get("postgres")=="ok" and ready.get("checks",{}).get("redis")=="ok"
    passed("readiness",ready)

    payloads=ds["events"]
    by_case={x["case"]:x for x in payloads}
    response=request("POST","/api/v1/events/batch",{"events":payloads})
    assert response.get("accepted")==len(payloads),response
    items=response.get("items",[])
    assert len(items)==len(payloads),response
    ids_by_case={}
    for event,item in zip(payloads,items):
        assert item.get("duplicate") is False,{"case":event["case"],"item":item}
        ids_by_case[event["case"]]=item["event_id"]
        created["events"].append(item["event_id"])
        created["alerts"].extend(item.get("alerts",[]))
    passed("synthetic_event_batch_ingestion",{"submitted":len(payloads),"accepted":response["accepted"]})

    # Read persisted alerts and assert exact rule IDs and severities, not merely alert existence.
    alert_response=request("GET","/api/v1/alerts?status=open&limit=500")
    all_alerts=alert_response.get("items",[])
    alerts_by_event={}
    for a in all_alerts:
        if a.get("event_id") in set(ids_by_case.values()):
            alerts_by_event.setdefault(a["event_id"],[]).append(a)
            if a.get("id") not in created["alerts"]: created["alerts"].append(a["id"])
    expected=ds["expected_detection"]
    for case,rule_ids in expected.items():
        found=alerts_by_event.get(ids_by_case[case],[])
        actual=sorted(a["rule_id"] for a in found)
        if actual!=sorted(rule_ids):
            raise AssertionError(f"{case}: expected rule IDs {sorted(rule_ids)}, got {actual}")
        if case=="authentication_rule" and any(a["severity"]!="high" for a in found):
            raise AssertionError(f"{case}: AUTH-001 severity should be high")
        if case=="endpoint_and_behavior_overlap" and any(a["severity"]!="high" for a in found):
            raise AssertionError(f"{case}: both expected alerts should be high")
        if case in ("correlation_positive_first","correlation_positive_second") and any(a["severity"]!="high" for a in found):
            raise AssertionError(f"{case}: domain/privilege rules should be high")
    passed("exact_detection_rule_and_severity_assertions",{
        case:{"expected_rule_ids":sorted(rule_ids),"actual_rule_ids":sorted(a["rule_id"] for a in alerts_by_event.get(ids_by_case[case],[]))}
        for case,rule_ids in expected.items()})

    # Benign event must not create any alert.
    benign_alerts=alerts_by_event.get(ids_by_case["benign_negative"],[])
    assert not benign_alerts,benign_alerts
    passed("benign_event_false_positive_guard",{"event_id":ids_by_case["benign_negative"],"alert_count":0})

    # Duplicate replay must return original event ID, be flagged duplicate, and create no new alert IDs.
    replay=request("POST","/api/v1/events",by_case["endpoint_and_behavior_overlap"])
    replay_item=replay["items"][0]
    assert replay_item["duplicate"] is True and replay_item["event_id"]==ids_by_case["endpoint_and_behavior_overlap"]
    assert replay_item.get("alerts")==[] and replay.get("alert_ids")==[]
    passed("duplicate_replay_idempotency",{"original_event_id":ids_by_case["endpoint_and_behavior_overlap"],
        "replay_duplicate":replay_item["duplicate"],"replay_alerts":replay_item.get("alerts")})

    # Verify exactly one persisted event for each unique source/test case.
    event_read=request("GET","/api/v1/events?limit=500")
    matching=[e for e in event_read.get("items",[]) if e.get("source")==marker]
    assert len(matching)==len(payloads),{"expected":len(payloads),"found":len(matching)}
    persisted_ids={e["id"] for e in matching}
    assert persisted_ids==set(ids_by_case.values())
    passed("event_persistence_and_no_duplicate_row",{"expected_events":len(payloads),"persisted_events":len(matching)})

    # Correlation is computed dynamically from persisted events. Assert exact lead and evidence links.
    corr=request("GET","/api/v1/correlations?domain=cloud_saas&limit=2000")
    leads=corr.get("items",[])
    positive_entity=by_case["correlation_positive_first"]["username"]
    lead=next((x for x in leads if x.get("entity_value")==positive_entity),None)
    assert lead is not None,{"entity":positive_entity,"lead_count":corr.get("lead_count")}
    expected_evidence=[ids_by_case["correlation_positive_first"],ids_by_case["correlation_positive_second"]]
    assert lead.get("rule_id")=="CORR-CLOUD-001"
    assert lead.get("event_types")==["credential_abuse","privilege_escalation"]
    assert lead.get("evidence_event_ids")==expected_evidence
    assert lead.get("observed_interval_seconds")==600
    assert lead.get("severity")=="high"
    negative_entities=[
        by_case["different_entity_first"]["username"],
        by_case["different_entity_second"]["username"],
        by_case["reversed_order_first"]["username"],
        by_case["outside_window_first"]["username"]
    ]
    negative_leads=[x for x in leads if x.get("entity_value") in negative_entities]
    assert not negative_leads,negative_leads
    passed("correlation_positive_and_negative_sequence_validation",{
        "rule_id":lead["rule_id"],"entity":lead["entity_value"],
        "evidence_event_ids":lead["evidence_event_ids"],
        "observed_interval_seconds":lead["observed_interval_seconds"],
        "negative_entities_without_leads":len(negative_entities)})

    report={"pack":"AEGIS B3 Detection and Correlation Acceptance","marker":marker,
        "base_url":BASE,"status":"PASS","checks":checks,"created_ids":created,
        "case_event_ids":ids_by_case,
        "notes":["Synthetic TEST-NET IP addresses only; no external systems contacted.",
                 "Correlation endpoint derives leads dynamically from persisted events; leads are not separately persisted rows.",
                 "Audit records are retained during cleanup; event deletion cascades associated alerts."]}
    OUT.write_text(json.dumps(report,indent=2))
    print("\nB3 ACCEPTANCE PASSED")
    print("Report:",OUT)
if __name__=="__main__":
    try: main()
    except Exception as e:
        report={"pack":"AEGIS B3 Detection and Correlation Acceptance","status":"FAIL",
            "marker":"AEGIS-B3-20261102","checks":checks,"created_ids":created,
            "failure":f"{type(e).__name__}: {e}",
            "notes":["Do not rerun blindly. Review recorded IDs and failure before cleanup."]}
        OUT.write_text(json.dumps(report,indent=2))
        print(f"FAIL: {type(e).__name__}: {e}",file=sys.stderr)
        sys.exit(1)
