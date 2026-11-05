#!/usr/bin/env python3
import json, os, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import requests
API=os.getenv("AEGIS_API_URL","http://localhost:8000").rstrip("/")
RUN="P06PERF-"+uuid.uuid4().hex[:10]; SOURCE="phase06-detection"
OUT=Path(__file__).resolve().parents[1]/"results/detection_performance_report.json"
s=requests.Session(); results=[]; ids=[]
try:
 for size in (20,100,250,500):
  now=datetime.now(timezone.utc)
  events=[{"event_time":(now+timedelta(microseconds=i)).isoformat(),"source":SOURCE,
   "event_type":"normal_activity","domain":"cloud_saas","severity":"informational",
   "src_ip":f"203.0.113.{i%200+1}","username":f"{RUN}-{size}-{i}",
   "message":f"Phase06 volume fixture {RUN} batch={size} index={i}",
   "raw":{"phase06_run":RUN,"fixture_index":i,"batch_size":size}} for i in range(size)]
  t=time.perf_counter(); r=s.post(API+"/api/v1/events/batch",json={"events":events},timeout=180)
  elapsed=time.perf_counter()-t; r.raise_for_status(); b=r.json(); items=b.get("items",[])
  ids += [x["event_id"] for x in items if not x.get("duplicate") and x.get("event_id")]
  results.append({"batch_size":size,"accepted":b.get("accepted"),"elapsed_seconds":round(elapsed,4),
   "events_per_second":round(size/elapsed,2) if elapsed else None,"alert_count":len(b.get("alert_ids",[])),
   "status":"PASS" if b.get("accepted")==size and len(items)==size else "FAIL"})
 report={"phase":"06","run_id":RUN,"status":"PASS" if all(x["status"]=="PASS" for x in results) else "FAIL",
  "results":results,"created_event_ids":ids,"note":"Single-run observed timings; no SLA or production load claim."}
except Exception as e:
 report={"phase":"06","run_id":RUN,"status":"ERROR","results":results,"created_event_ids":ids,"error":f"{type(e).__name__}: {e}"}
OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2)); sys.exit(0 if report["status"]=="PASS" else 1)
