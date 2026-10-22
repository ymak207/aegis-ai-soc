import hashlib
import json
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
from psycopg.types.json import Jsonb
import redis
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(
    title="AEGIS AI SOC API",
    version="0.2.0",
    description="Self-hosted security event, detection, case and AI-assisted investigation platform.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("CORS_ORIGINS", "http://localhost:5173").split(","),
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization"],
)
DB_HOST = os.getenv("DB_HOST", "postgres")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "aegis")
DB_USER = os.getenv("DB_USER", "aegis")
DB_PASSWORD = os.getenv("DB_PASSWORD", "local-dev-change-me")
REDIS_URL = os.getenv("REDIS_URL", "")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS security_events (
 id TEXT PRIMARY KEY, event_time TIMESTAMPTZ NOT NULL, source TEXT NOT NULL,
 event_type TEXT NOT NULL, severity TEXT NOT NULL, src_ip TEXT, dst_ip TEXT,
 username TEXT, host TEXT, message TEXT NOT NULL, raw JSONB NOT NULL,
 fingerprint TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_events_time ON security_events(event_time DESC);
CREATE INDEX IF NOT EXISTS ix_events_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS ix_events_fingerprint ON security_events(fingerprint);
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES security_events(id) ON DELETE CASCADE,
 rule_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 description TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(event_id, rule_id)
);
CREATE INDEX IF NOT EXISTS ix_alerts_status ON alerts(status, created_at DESC);
CREATE TABLE IF NOT EXISTS cases (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 description TEXT NOT NULL DEFAULT '', alert_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
 assignee TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS case_timeline (
 id BIGSERIAL PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
 entry_type TEXT NOT NULL, content TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'system',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS threat_indicators (
 id TEXT PRIMARY KEY, indicator_type TEXT NOT NULL, value TEXT NOT NULL,
 confidence INTEGER NOT NULL DEFAULT 50, source TEXT NOT NULL DEFAULT 'manual',
 description TEXT NOT NULL DEFAULT '', created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(indicator_type, value)
);
CREATE TABLE IF NOT EXISTS knowledge_documents (
 id TEXT PRIMARY KEY, title TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'manual',
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS evaluation_runs (
 id TEXT PRIMARY KEY, suite TEXT NOT NULL, metrics JSONB NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS agent_runs (
 id TEXT PRIMARY KEY, agent_name TEXT NOT NULL, task TEXT NOT NULL,
 status TEXT NOT NULL, duration_ms INTEGER NOT NULL DEFAULT 0,
 trace JSONB NOT NULL DEFAULT '[]'::jsonb, result JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_agent_runs_created ON agent_runs(created_at DESC);
CREATE TABLE IF NOT EXISTS audit_log (
 id BIGSERIAL PRIMARY KEY, action TEXT NOT NULL, entity_type TEXT NOT NULL,
 entity_id TEXT NOT NULL, details JSONB NOT NULL DEFAULT '{}'::jsonb,
 created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""
SEVERITIES = {"informational", "low", "medium", "high", "critical"}
RULES = [
    {"id": "AUTH-001", "title": "Repeated authentication failures", "severity": "high",
     "types": {"authentication_failure", "failed_login"}, "description": "Authentication failure event requires analyst review."},
    {"id": "NET-001", "title": "Known malicious indicator observed", "severity": "critical",
     "types": {"threat_indicator_match"}, "description": "Event matched a configured threat indicator."},
    {"id": "ENDPOINT-001", "title": "Suspicious process execution", "severity": "high",
     "types": {"suspicious_process", "malware_detected"}, "description": "Endpoint event indicates suspicious process or malware activity."},
    {"id": "PRIV-001", "title": "Privilege escalation signal", "severity": "high",
     "types": {"privilege_escalation"}, "description": "Privilege escalation signal requires investigation."},
]

class EventIn(BaseModel):
    event_time: datetime | None = None
    source: str = Field(default="manual", min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = "medium"
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    host: str | None = None
    message: str = Field(min_length=1, max_length=10000)
    raw: dict[str, Any] = Field(default_factory=dict)

class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=500)

class CaseIn(BaseModel):
    title: str = Field(min_length=3, max_length=250)
    severity: str = "medium"
    description: str = Field(default="", max_length=10000)
    alert_ids: list[str] = Field(default_factory=list)
    assignee: str | None = None

class CaseUpdate(BaseModel):
    status: str | None = None
    assignee: str | None = None
    note: str | None = None

class IndicatorIn(BaseModel):
    indicator_type: str = Field(pattern="^(ip|domain|hash|url)$")
    value: str = Field(min_length=1, max_length=2048)
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = Field(default="manual", max_length=200)
    description: str = Field(default="", max_length=2000)

class DocumentIn(BaseModel):
    title: str = Field(min_length=1, max_length=250)
    content: str = Field(min_length=20, max_length=100000)
    source: str = Field(default="manual", max_length=200)

class InvestigateIn(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    alert_id: str | None = None

def connect():
    # Pass credentials separately; URL concatenation breaks with reserved password characters.
    return psycopg.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME, user=DB_USER,
        password=DB_PASSWORD, connect_timeout=5,
    )

def initialize_database():
    with connect() as conn:
        conn.execute(SCHEMA_SQL)

def audit(conn, action: str, entity_type: str, entity_id: str, details: dict | None = None):
    conn.execute("INSERT INTO audit_log(action,entity_type,entity_id,details) VALUES (%s,%s,%s,%s)",
                 (action, entity_type, entity_id, Jsonb(details or {})))

def normalized_event(payload: EventIn) -> dict:
    severity = payload.severity.lower()
    if severity not in SEVERITIES:
        severity = "medium"
    event_time = payload.event_time or datetime.now(timezone.utc)
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    event_type = re.sub(r"[^a-z0-9_]+", "_", payload.event_type.lower()).strip("_")
    raw = payload.raw or {}
    stable = json.dumps({"source": payload.source, "type": event_type, "time": event_time.isoformat(),
                         "src_ip": payload.src_ip, "username": payload.username, "message": payload.message},
                        sort_keys=True)
    return {"id": str(uuid.uuid4()), "event_time": event_time, "source": payload.source,
            "event_type": event_type, "severity": severity, "src_ip": payload.src_ip,
            "dst_ip": payload.dst_ip, "username": payload.username, "host": payload.host,
            "message": payload.message, "raw": raw, "fingerprint": hashlib.sha256(stable.encode()).hexdigest()}

def rule_matches(event: dict) -> list[dict]:
    matches = []
    for rule in RULES:
        if event["event_type"] in rule["types"]:
            matches.append(rule)
    message = event["message"].lower()
    if any(term in message for term in ("powershell -enc", "mimikatz", "credential dump")):
        matches.append({"id": "BEHAVIOR-001", "title": "Suspicious command-line pattern",
                        "severity": "high", "description": "Message matched a high-risk command-line heuristic."})
    return matches

def enrich_indicator(conn, event: dict) -> bool:
    candidates = [("ip", event.get("src_ip")), ("ip", event.get("dst_ip"))]
    raw = event.get("raw") or {}
    for key in ("domain", "url", "hash"):
        if raw.get(key):
            candidates.append((key, str(raw[key])))
    for kind, value in candidates:
        if value and conn.execute("SELECT 1 FROM threat_indicators WHERE indicator_type=%s AND lower(value)=lower(%s)",
                                  (kind, value)).fetchone():
            event["event_type"] = "threat_indicator_match"
            event["message"] += f" [matched {kind} indicator]"
            return True
    return False

@app.on_event("startup")
def startup():
    # Compose starts the API only after PostgreSQL reports healthy.
    initialize_database()

@app.get("/health/live", tags=["health"])
def liveness():
    return {"status": "alive", "service": "aegis-api"}

@app.get("/health/ready", tags=["health"])
def readiness():
    checks = {}
    try:
        with connect() as conn:
            conn.execute("SELECT 1")
        checks["postgres"] = "ok"
    except Exception:
        checks["postgres"] = "unavailable"
    try:
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=2).ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    return {"status": "ready" if all(v == "ok" for v in checks.values()) else "degraded", "checks": checks}

@app.get("/metrics", include_in_schema=False, response_class=PlainTextResponse)
def metrics():
    try:
        with connect() as conn:
            events = conn.execute("SELECT count(*) FROM security_events").fetchone()[0]
            alerts = conn.execute("SELECT count(*) FROM alerts WHERE status='open'").fetchone()[0]
            cases = conn.execute("SELECT count(*) FROM cases WHERE status='open'").fetchone()[0]
        return f"aegis_events_total {events}\naegis_open_alerts {alerts}\naegis_open_cases {cases}\n"
    except Exception as exc:
        raise HTTPException(503, "metrics unavailable") from exc

@app.get("/api/v1", tags=["system"])
def system_info():
    return {"name": "AEGIS AI SOC", "version": app.version, "status": "operational",
            "utc_time": datetime.now(timezone.utc).isoformat(),
            "capabilities": ["event-ingestion", "rule-based-detection", "alert-management", "case-management",
                             "threat-intelligence", "audit-trail", "knowledge-retrieval", "local-llm-investigation",
                             "mcp-tool-endpoint", "metrics", "baseline-evaluation", "agent-run-traces", "data-quality", "graph-lite"]}

@app.get("/api/v1/overview")
def overview():
    with connect() as conn:
        counts = {}
        for key, query in {
            "events": "SELECT count(*) FROM security_events",
            "alerts_open": "SELECT count(*) FROM alerts WHERE status='open'",
            "alerts_critical": "SELECT count(*) FROM alerts WHERE status='open' AND severity='critical'",
            "cases_open": "SELECT count(*) FROM cases WHERE status='open'",
            "indicators": "SELECT count(*) FROM threat_indicators",
            "documents": "SELECT count(*) FROM knowledge_documents",
        }.items():
            counts[key] = conn.execute(query).fetchone()[0]
    return counts

@app.post("/api/v1/events")
def ingest_event(payload: EventIn):
    return ingest_batch(EventBatch(events=[payload]))

@app.post("/api/v1/events/batch")
def ingest_batch(batch: EventBatch):
    created, alert_ids = [], []
    with connect() as conn:
        for payload in batch.events:
            event = normalized_event(payload)
            indicator_match = enrich_indicator(conn, event)
            existing = conn.execute("SELECT id FROM security_events WHERE fingerprint=%s", (event["fingerprint"],)).fetchone()
            if existing:
                created.append({"event_id": existing[0], "duplicate": True, "alerts": []})
                continue
            conn.execute("""INSERT INTO security_events(id,event_time,source,event_type,severity,src_ip,dst_ip,username,host,message,raw,fingerprint)
                VALUES(%(id)s,%(event_time)s,%(source)s,%(event_type)s,%(severity)s,%(src_ip)s,%(dst_ip)s,%(username)s,%(host)s,%(message)s,%(raw)s,%(fingerprint)s)""",
                {**event, "raw": Jsonb(event["raw"])})
            made = []
            for rule in rule_matches(event):
                aid = str(uuid.uuid4())
                conn.execute("""INSERT INTO alerts(id,event_id,rule_id,title,severity,description)
                    VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(event_id,rule_id) DO NOTHING""",
                    (aid, event["id"], rule["id"], rule["title"], rule["severity"], rule["description"]))
                row = conn.execute("SELECT id FROM alerts WHERE event_id=%s AND rule_id=%s", (event["id"], rule["id"])).fetchone()
                if row:
                    made.append(row[0]); alert_ids.append(row[0])
            audit(conn, "event.ingested", "event", event["id"], {"event_type": event["event_type"], "alert_count": len(made), "indicator_match": indicator_match})
            created.append({"event_id": event["id"], "duplicate": False, "alerts": made})
    return {"accepted": len(created), "items": created, "alert_ids": alert_ids}

@app.get("/api/v1/events")
def list_events(limit: int = Query(default=50, ge=1, le=500), event_type: str | None = None):
    with connect() as conn:
        if event_type:
            rows = conn.execute("""SELECT id,event_time,source,event_type,severity,src_ip,dst_ip,username,host,message
                FROM security_events WHERE event_type=%s ORDER BY event_time DESC LIMIT %s""", (event_type, limit)).fetchall()
        else:
            rows = conn.execute("""SELECT id,event_time,source,event_type,severity,src_ip,dst_ip,username,host,message
                FROM security_events ORDER BY event_time DESC LIMIT %s""", (limit,)).fetchall()
    return {"items": [dict(zip(["id","event_time","source","event_type","severity","src_ip","dst_ip","username","host","message"], r)) for r in rows]}

@app.get("/api/v1/alerts")
def list_alerts(status: str | None = "open", limit: int = Query(default=100, ge=1, le=500)):
    with connect() as conn:
        rows = conn.execute("""SELECT a.id,a.event_id,a.rule_id,a.title,a.severity,a.status,a.description,a.created_at,
            e.event_type,e.src_ip,e.username,e.host,e.message FROM alerts a JOIN security_events e ON e.id=a.event_id
            WHERE (%s::text IS NULL OR a.status=%s) ORDER BY a.created_at DESC LIMIT %s""", (status,status,limit)).fetchall()
    keys = ["id","event_id","rule_id","title","severity","status","description","created_at","event_type","src_ip","username","host","message"]
    return {"items": [dict(zip(keys,r)) for r in rows]}

@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(alert_id: str, body: dict):
    status = body.get("status")
    if status not in {"open", "investigating", "resolved", "false_positive"}:
        raise HTTPException(400, "Invalid alert status")
    with connect() as conn:
        row = conn.execute("UPDATE alerts SET status=%s WHERE id=%s RETURNING id,status", (status,alert_id)).fetchone()
        if not row: raise HTTPException(404, "Alert not found")
        audit(conn, "alert.updated", "alert", alert_id, {"status": status})
    return {"id": row[0], "status": row[1]}

@app.post("/api/v1/cases", status_code=201)
def create_case(body: CaseIn):
    if body.severity.lower() not in SEVERITIES: raise HTTPException(400, "Invalid severity")
    cid = str(uuid.uuid4())
    with connect() as conn:
        conn.execute("""INSERT INTO cases(id,title,severity,description,alert_ids,assignee) VALUES(%s,%s,%s,%s,%s,%s)""",
                     (cid,body.title,body.severity.lower(),body.description,Jsonb(body.alert_ids),body.assignee))
        conn.execute("INSERT INTO case_timeline(case_id,entry_type,content) VALUES(%s,'created',%s)", (cid,body.description or "Case created"))
        audit(conn, "case.created", "case", cid, {"alert_ids": body.alert_ids})
    return {"id":cid,"title":body.title,"severity":body.severity.lower(),"status":"open"}

@app.get("/api/v1/cases")
def list_cases(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as conn:
        rows = conn.execute("SELECT id,title,severity,status,description,alert_ids,assignee,created_at,updated_at FROM cases ORDER BY updated_at DESC LIMIT %s", (limit,)).fetchall()
    keys=["id","title","severity","status","description","alert_ids","assignee","created_at","updated_at"]
    return {"items":[dict(zip(keys,r)) for r in rows]}

@app.patch("/api/v1/cases/{case_id}")
def update_case(case_id: str, body: CaseUpdate):
    with connect() as conn:
        row = conn.execute("SELECT id FROM cases WHERE id=%s",(case_id,)).fetchone()
        if not row: raise HTTPException(404,"Case not found")
        if body.status and body.status not in {"open","in_progress","contained","resolved","closed"}: raise HTTPException(400,"Invalid case status")
        if body.status or body.assignee is not None:
            conn.execute("UPDATE cases SET status=COALESCE(%s,status),assignee=COALESCE(%s,assignee),updated_at=now() WHERE id=%s",(body.status,body.assignee,case_id))
        if body.note:
            conn.execute("INSERT INTO case_timeline(case_id,entry_type,content,actor) VALUES(%s,'note',%s,'analyst')",(case_id,body.note))
        audit(conn,"case.updated","case",case_id,body.model_dump(exclude_none=True))
    return {"id":case_id,"updated":True}

@app.get("/api/v1/cases/{case_id}/timeline")
def case_timeline(case_id: str):
    with connect() as conn:
        if not conn.execute("SELECT 1 FROM cases WHERE id=%s",(case_id,)).fetchone(): raise HTTPException(404,"Case not found")
        rows=conn.execute("SELECT id,entry_type,content,actor,created_at FROM case_timeline WHERE case_id=%s ORDER BY created_at",(case_id,)).fetchall()
    keys=["id","entry_type","content","actor","created_at"]
    return {"items":[dict(zip(keys,r)) for r in rows]}

@app.post("/api/v1/intel/indicators", status_code=201)
def add_indicator(body: IndicatorIn):
    iid=str(uuid.uuid4())
    with connect() as conn:
        conn.execute("""INSERT INTO threat_indicators(id,indicator_type,value,confidence,source,description)
          VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(indicator_type,value) DO UPDATE SET confidence=EXCLUDED.confidence,source=EXCLUDED.source,description=EXCLUDED.description""",
          (iid,body.indicator_type,body.value,body.confidence,body.source,body.description))
        row=conn.execute("SELECT id,indicator_type,value,confidence,source,description,created_at FROM threat_indicators WHERE indicator_type=%s AND value=%s",(body.indicator_type,body.value)).fetchone()
        audit(conn,"intel.indicator_added","indicator",row[0],{"type":body.indicator_type,"value":body.value})
    return dict(zip(["id","indicator_type","value","confidence","source","description","created_at"],row))

@app.get("/api/v1/intel/indicators")
def list_indicators(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as conn:
        rows=conn.execute("SELECT id,indicator_type,value,confidence,source,description,created_at FROM threat_indicators ORDER BY created_at DESC LIMIT %s",(limit,)).fetchall()
    keys=["id","indicator_type","value","confidence","source","description","created_at"]
    return {"items":[dict(zip(keys,r)) for r in rows]}

@app.post("/api/v1/knowledge/documents", status_code=201)
def add_document(body: DocumentIn):
    did=str(uuid.uuid4())
    with connect() as conn:
        conn.execute("INSERT INTO knowledge_documents(id,title,content,source) VALUES(%s,%s,%s,%s)",(did,body.title,body.content,body.source))
        audit(conn,"knowledge.document_added","document",did,{"title":body.title})
    return {"id":did,"title":body.title,"source":body.source}

@app.get("/api/v1/knowledge/search")
def search_knowledge(q: str = Query(min_length=2, max_length=500), limit: int = Query(default=5, ge=1, le=20)):
    terms=[t.lower() for t in re.findall(r"[a-zA-Z0-9_.-]+",q) if len(t)>1]
    with connect() as conn:
        rows=conn.execute("SELECT id,title,content,source FROM knowledge_documents ORDER BY created_at DESC LIMIT 500").fetchall()
    ranked=[]
    for did,title,content,source in rows:
        text=(title+" "+content).lower()
        score=sum(text.count(term) for term in terms)
        if score: ranked.append({"id":did,"title":title,"content":content[:4000],"source":source,"score":score})
    ranked.sort(key=lambda x:x["score"],reverse=True)
    return {"query":q,"items":ranked[:limit],"mode":"keyword-baseline","note":"Local retrieval baseline; vector embeddings are an optional profile."}

@app.post("/api/v1/investigations")
def investigate(body: InvestigateIn):
    started = time.perf_counter()
    with connect() as conn:
        alert=None
        if body.alert_id:
            row=conn.execute("""SELECT a.id,a.title,a.severity,a.description,e.event_type,e.src_ip,e.username,e.host,e.message
             FROM alerts a JOIN security_events e ON e.id=a.event_id WHERE a.id=%s""",(body.alert_id,)).fetchone()
            if not row: raise HTTPException(404,"Alert not found")
            alert=dict(zip(["id","title","severity","description","event_type","src_ip","username","host","message"],row))
        terms=[t.lower() for t in re.findall(r"[a-zA-Z0-9_.-]+",body.question) if len(t)>2]
        docs=conn.execute("SELECT title,content,source FROM knowledge_documents ORDER BY created_at DESC LIMIT 100").fetchall()
        evidence=[]
        for title,content,source in docs:
            score=sum((title+" "+content).lower().count(t) for t in terms)
            if score: evidence.append({"title":title,"source":source,"content":content[:1500],"score":score})
        evidence.sort(key=lambda x:x["score"],reverse=True)
    answer={"mode":"evidence-based-baseline","question":body.question,"alert":alert,
            "evidence":evidence[:5],
            "assessment":"No local LLM response was requested or available. This baseline returns evidence for analyst review and does not execute response actions.",
            "recommended_next_steps":["Validate event source and timestamp","Correlate related events and indicators","Review supporting evidence","Record analyst conclusion in a case"]}
    try:
        import urllib.request
        request_data=json.dumps({"model":OLLAMA_MODEL,"stream":False,"messages":[
            {"role":"system","content":"You are a defensive SOC assistant. Use only supplied evidence. State uncertainty. Never claim an action was executed."},
            {"role":"user","content":json.dumps({"question":body.question,"alert":alert,"evidence":evidence[:5]})}]}).encode()
        req=urllib.request.Request(OLLAMA_URL+"/api/chat",data=request_data,headers={"Content-Type":"application/json"})
        with urllib.request.urlopen(req,timeout=45) as response:
            result=json.loads(response.read())
        answer["mode"]="local-ollama"
        answer["assessment"]=result.get("message",{}).get("content","No response content")
    except Exception as exc:
        answer["llm_status"]="unavailable; returned deterministic evidence baseline"
        answer["llm_error_type"]=type(exc).__name__
    duration_ms = int((time.perf_counter() - started) * 1000)
    trace = [
        {"step": "load_alert_context", "status": "ok" if alert else ("skipped" if not body.alert_id else "missing")},
        {"step": "retrieve_knowledge", "status": "ok", "evidence_count": len(evidence[:5]), "retriever": "keyword-baseline"},
        {"step": "local_llm", "status": "ok" if answer["mode"] == "local-ollama" else "fallback",
         "model": OLLAMA_MODEL if answer["mode"] == "local-ollama" else None},
        {"step": "recommendations", "status": "ok", "response_actions_executed": False},
    ]
    run_id = str(uuid.uuid4())
    answer["run_id"] = run_id
    answer["duration_ms"] = duration_ms
    answer["trace"] = trace
    with connect() as conn:
        conn.execute("""INSERT INTO agent_runs(id,agent_name,task,status,duration_ms,trace,result)
            VALUES(%s,%s,%s,%s,%s,%s,%s)""",
            (run_id, "investigation-assistant", body.question, "completed", duration_ms,
             Jsonb(trace), Jsonb({"mode": answer["mode"], "evidence_count": len(evidence[:5])})))
        audit(conn,"investigation.run","alert" if body.alert_id else "query",body.alert_id or run_id,
              {"mode":answer["mode"], "duration_ms": duration_ms, "evidence_count": len(evidence[:5])})
    return answer


# Versioned, deterministic baseline benchmark. These are synthetic test cases, not a
# substitute for a representative, labeled production dataset.
DETECTION_EVAL_DATASET = [
    {"type":"authentication_failure","message":"failed login","expected":True},
    {"type":"failed_login","message":"invalid password","expected":True},
    {"type":"suspicious_process","message":"unknown process launched","expected":True},
    {"type":"malware_detected","message":"test malware signature","expected":True},
    {"type":"privilege_escalation","message":"privilege changed","expected":True},
    {"type":"threat_indicator_match","message":"reserved test IOC match","expected":True},
    {"type":"normal_activity","message":"successful routine login","expected":False},
    {"type":"normal_activity","message":"scheduled backup completed","expected":False},
    {"type":"normal_activity","message":"user opened dashboard","expected":False},
    {"type":"normal_activity","message":"routine health check","expected":False},
    {"type":"process_start","message":"powershell -enc synthetic-test","expected":True},
    {"type":"process_start","message":"credential dump detected in simulation","expected":True},
]

@app.post("/api/v1/evaluations/run")
def run_evaluation():
    """Run a repeatable rule-baseline benchmark and persist its exact dataset version."""
    tp = fp = tn = fn = 0
    examples = []
    for index, sample in enumerate(DETECTION_EVAL_DATASET):
        event = {"event_type": sample["type"], "message": sample["message"]}
        predicted = bool(rule_matches(event))
        expected = sample["expected"]
        if predicted and expected: tp += 1
        elif predicted and not expected: fp += 1
        elif not predicted and not expected: tn += 1
        else: fn += 1
        examples.append({"case": index + 1, "expected_detection": expected, "predicted_detection": predicted,
                         "pass": predicted == expected, "event_type": sample["type"]})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    result = {"dataset_version": "aegis-synthetic-detection-v1", "sample_count": len(examples),
              "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
              "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
              "accuracy": round((tp + tn) / len(examples), 4),
              "pass_count": sum(1 for item in examples if item["pass"]),
              "examples": examples,
              "limitations": ["Synthetic, hand-authored cases only", "Rule/heuristic baseline, not a trained ML model",
                              "Do not interpret these scores as production detection quality"]}
    run_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute("INSERT INTO evaluation_runs(id,suite,metrics) VALUES(%s,%s,%s)",
                     (run_id, "detection-baseline", Jsonb(result)))
        audit(conn, "evaluation.completed", "evaluation", run_id,
              {"suite": "detection-baseline", "sample_count": len(examples), "f1": result["f1"]})
    return {"id": run_id, "suite": "detection-baseline", **result}

@app.get("/api/v1/evaluations/results")
def evaluation_results(limit: int = Query(default=10, ge=1, le=100)):
    with connect() as conn:
        rows = conn.execute("SELECT id,suite,metrics,created_at FROM evaluation_runs ORDER BY created_at DESC LIMIT %s",
                            (limit,)).fetchall()
    return {"items": [{"id": r[0], "suite": r[1], "metrics": r[2], "created_at": r[3]} for r in rows]}

@app.get("/api/v1/agents/runs")
def agent_runs(limit: int = Query(default=20, ge=1, le=100)):
    with connect() as conn:
        rows = conn.execute("""SELECT id,agent_name,task,status,duration_ms,trace,result,created_at
            FROM agent_runs ORDER BY created_at DESC LIMIT %s""", (limit,)).fetchall()
    keys = ["id","agent_name","task","status","duration_ms","trace","result","created_at"]
    return {"items": [dict(zip(keys, row)) for row in rows]}

@app.get("/api/v1/data/quality")
def data_quality():
    with connect() as conn:
        row = conn.execute("""SELECT count(*),
            count(*) FILTER (WHERE src_ip IS NULL OR src_ip=''),
            count(*) FILTER (WHERE host IS NULL OR host=''),
            count(*) FILTER (WHERE username IS NULL OR username='')
            FROM security_events""").fetchone()
        events, missing_ip, missing_host, missing_user = row
        alert_count = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
    return {"event_count": events, "alert_count": alert_count,
            "completeness": {"src_ip_pct": round(100 * (events-missing_ip)/events, 2) if events else None,
                             "host_pct": round(100 * (events-missing_host)/events, 2) if events else None,
                             "username_pct": round(100 * (events-missing_user)/events, 2) if events else None},
            "note": "Completeness is measured from stored events; null means no events exist."}

@app.get("/api/v1/graph/summary")
def graph_summary(limit: int = Query(default=500, ge=1, le=2000)):
    """A relational graph-lite view derived from event records; Neo4j is not required."""
    with connect() as conn:
        rows = conn.execute("""SELECT event_type, COALESCE(host,'unknown') AS host,
            COALESCE(username,'unknown') AS username, count(*) AS weight
            FROM (SELECT event_type,host,username FROM security_events ORDER BY event_time DESC LIMIT %s) e
            GROUP BY event_type,host,username ORDER BY weight DESC LIMIT 100""", (limit,)).fetchall()
    nodes = set()
    edges = []
    for event_type, host, username, weight in rows:
        for kind, value in (("event_type", event_type), ("host", host), ("user", username)):
            nodes.add((kind, value))
        edges.extend([
            {"source": f"event_type:{event_type}", "target": f"host:{host}", "relation": "observed_on", "weight": weight},
            {"source": f"event_type:{event_type}", "target": f"user:{username}", "relation": "associated_with", "weight": weight},
        ])
    return {"mode": "postgres-derived-graph-lite", "node_count": len(nodes),
            "edge_count": len(edges), "nodes": [{"id": f"{kind}:{value}", "type": kind, "label": value}
                                                  for kind, value in sorted(nodes)],
            "edges": edges, "note": "Derived event associations only; this endpoint does not query Neo4j or infer causality."}

@app.get("/api/v1/mcp/tools")
def mcp_tools():
    return {"protocol":"AEGIS internal tool catalog v1","tools":[
        {"name":"search_alerts","description":"Search recent alerts","inputSchema":{"type":"object","properties":{"status":{"type":"string"},"limit":{"type":"integer"}}}},
        {"name":"search_knowledge","description":"Search stored SOC documents","inputSchema":{"type":"object","properties":{"q":{"type":"string"}}}},
        {"name":"get_overview","description":"Get SOC counters","inputSchema":{"type":"object","properties":{}}},
        {"name":"get_graph_summary","description":"Get derived event relationship summary","inputSchema":{"type":"object","properties":{}}},
        {"name":"get_data_quality","description":"Get event-field completeness metrics","inputSchema":{"type":"object","properties":{}}},
        {"name":"run_detection_evaluation","description":"Run the versioned synthetic detection benchmark","inputSchema":{"type":"object","properties":{}}}
    ],"note":"This is an HTTP tool catalog, not a full MCP transport server."}

@app.get("/api/v1/audit")
def audit_entries(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as conn:
        rows=conn.execute("SELECT id,action,entity_type,entity_id,details,created_at FROM audit_log ORDER BY created_at DESC LIMIT %s",(limit,)).fetchall()
    keys=["id","action","entity_type","entity_id","details","created_at"]
    return {"items":[dict(zip(keys,r)) for r in rows]}
