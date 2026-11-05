#!/usr/bin/env python3
import json, os, sys, time, uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
import requests

API=os.getenv("AEGIS_API_URL","http://localhost:8000").rstrip("/")
SOURCE="phase06-detection"; RUN="P06-"+uuid.uuid4().hex[:12]
HERE=Path(__file__).resolve().parents[1]
OUT=HERE/"results/detection_acceptance_report.json"
DOMAINS=json.loads((HERE/"data/domain_event_families.json").read_text())
GENERAL=json.loads((HERE/"data/general_rule_contract.json").read_text())
checks=[]; created=[]; alerts=[]; s=requests.Session()
def check(n,ok,d=None): checks.append({"name":n,"status":"PASS" if ok else "FAIL","detail":d})
def ev(domain,typ,msg,i):
 return {"event_time":(datetime.now(timezone.utc)+timedelta(seconds=i)).isoformat(),"source":SOURCE,
 "event_type":typ,"domain":domain,"severity":"medium","src_ip":f"198.51.100.{i%200+1}",
 "username":f"p06-{i}","host":f"p06-host-{i}","message":msg,
 "raw":{"phase06_run":RUN,"fixture_index":i}}
start=time.time()
try:
 fixtures=[]; exp=[]; i=1
 for d,families in DOMAINS.items():
  for f in families:
   fixtures.append(ev(d,f,f"Synthetic domain fixture {d} {f} {RUN}",i))
   exp.append({"kind":"domain","family":f,"rule":"DOMAIN-"+d.upper()+"-001"}); i+=1
 for f,r in GENERAL.items():
  fixtures.append(ev("cloud_saas",f,f"Synthetic general rule fixture {f} {RUN}",i))
  exp.append({"kind":"general","family":f,"rule":r}); i+=1
 fixtures += [ev("cloud_saas","normal_activity",f"Routine health check {RUN}",i),
              ev("cloud_saas","normal_activity",f"Security awareness report mentions mimikatz as an example {RUN}",i+1),
              ev("cloud_saas","normal_activity",f"Documentation explains powershell -enc as a suspicious pattern {RUN}",i+2)]
 exp += [{"kind":"benign","family":"routine_health_check"},
         {"kind":"known_fp","family":"mimikatz_educational_text","rule":"BEHAVIOR-001"},
         {"kind":"known_fp","family":"powershell_educational_text","rule":"BEHAVIOR-001"}]
 r=s.post(API+"/api/v1/events/batch",json={"events":fixtures},timeout=120); r.raise_for_status()
 body=r.json(); items=body.get("items",[])
 check("batch_accepts_all_fixtures",body.get("accepted")==len(fixtures) and len(items)==len(fixtures),
       {"expected":len(fixtures),"accepted":body.get("accepted"),"items":len(items)})
 for x in items:
  if not x.get("duplicate"): created.append(x["event_id"])
  alerts.extend(x.get("alerts",[]))
 for n,e,x in zip(range(len(exp)),exp,items):
  a=x.get("alerts",[])
  if e["kind"]=="benign": check(e["family"]+"_no_alert",len(a)==0,{"alerts":a})
  else: check(e["kind"]+":"+e["family"]+"_alert_created",len(a)>=1,{"alerts":a,"expected_rule":e.get("rule")})
 # Verify persisted alert rule IDs and severity.
 ar=s.get(API+"/api/v1/alerts",params={"limit":500},timeout=60); ar.raise_for_status()
 ap=ar.json(); records=ap if isinstance(ap,list) else ap.get("items",ap.get("alerts",[]))
 mine=[a for a in records if a.get("event_id") in set(created)]
 mapping={}
 for a in mine: mapping.setdefault(a.get("event_id"),[]).append({"rule_id":a.get("rule_id"),"severity":a.get("severity")})
 for j,e in enumerate(exp):
  if e.get("rule"):
   found=mapping.get(items[j].get("event_id"),[])
   check(e["kind"]+":"+e["family"]+"_rule_mapping",any(a["rule_id"]==e["rule"] for a in found),
         {"expected":e["rule"],"observed":found})
 replay=s.post(API+"/api/v1/events/batch",json={"events":[fixtures[0]]},timeout=60); replay.raise_for_status()
 ri=replay.json().get("items",[{}])[0]
 check("exact_replay_idempotent",ri.get("duplicate") is True and ri.get("event_id")==items[0].get("event_id") and ri.get("alerts")==[],ri)
 report={"phase":"06","run_id":RUN,"status":"PASS" if all(c["status"]=="PASS" for c in checks) else "FAIL",
 "fixture_count":len(fixtures),"domain_family_count":sum(map(len,DOMAINS.values())),
 "created_event_ids":created,"alert_ids":alerts,"known_heuristic_false_positive_cases":2,
 "duration_seconds":round(time.time()-start,3),"checks":checks,
 "limitations":["Synthetic contract fixtures only; not production efficacy validation.",
 "Domain matches are generic analyst-review alerts.","Substring heuristic matches educational text."]}
except Exception as e:
 report={"phase":"06","run_id":RUN,"status":"ERROR","created_event_ids":created,"alert_ids":alerts,
 "error":f"{type(e).__name__}: {e}","checks":checks}
OUT.parent.mkdir(parents=True,exist_ok=True); OUT.write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report,indent=2)); sys.exit(0 if report["status"]=="PASS" else 1)
