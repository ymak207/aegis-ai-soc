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
OLLAMA_EMBED_MODEL = os.getenv("OLLAMA_EMBED_MODEL", "nomic-embed-text")
QDRANT_URL = os.getenv("QDRANT_URL", "http://qdrant:6333").rstrip("/")
QDRANT_COLLECTION = os.getenv("QDRANT_COLLECTION", "aegis_knowledge")
KAFKA_ENABLED = os.getenv("KAFKA_ENABLED", "false").lower() == "true"
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "aegis.security.events")
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



# Domain catalog is descriptive configuration, not a claim that domain-specific
# detections are already implemented. It gives adapters and evaluation suites a
# stable contract to grow against without changing the common event envelope.
DOMAIN_CATALOG = {
    "ecommerce": {
        "label": "E-commerce & digital commerce",
        "event_families": ["account_takeover", "payment_abuse", "promotion_abuse", "checkout_anomaly", "admin_access"],
        "sources": ["web application", "identity provider", "payment gateway", "WAF/CDN", "order service"],
        "evaluation_dimensions": ["precision", "recall", "false_positive_rate", "time_to_detect", "entity_resolution"],
        "required_context": ["tenant_id", "user_id", "session_id", "order_id", "payment_reference"],
    },
    "telecom": {
        "label": "Telecommunications",
        "event_families": ["sim_swap", "subscriber_account_abuse", "signalling_anomaly", "cdr_anomaly", "privileged_network_change"],
        "sources": ["AAA/RADIUS", "SIM provisioning", "network management", "CDR pipeline", "identity provider"],
        "evaluation_dimensions": ["precision", "recall", "false_positive_rate", "time_to_detect", "sequence_detection"],
        "required_context": ["subscriber_id", "sim_id", "device_id", "network_element", "session_id"],
    },
    "logistics": {
        "label": "Logistics & supply chain",
        "event_families": ["shipment_route_deviation", "warehouse_access_abuse", "fleet_device_compromise", "manifest_tampering", "partner_api_abuse"],
        "sources": ["fleet telemetry", "warehouse management", "shipment tracking", "partner API gateway", "identity provider"],
        "evaluation_dimensions": ["precision", "recall", "false_positive_rate", "time_to_detect", "entity_resolution"],
        "required_context": ["shipment_id", "vehicle_id", "warehouse_id", "partner_id", "device_id"],
    },
    "cloud_saas": {
        "label": "Cloud & SaaS",
        "event_families": ["credential_abuse", "privilege_escalation", "public_resource_exposure", "control_plane_anomaly", "data_exfiltration"],
        "sources": ["cloud audit logs", "IAM", "Kubernetes audit", "endpoint detection", "SaaS audit API"],
        "evaluation_dimensions": ["precision", "recall", "false_positive_rate", "time_to_detect", "attack_technique_coverage"],
        "required_context": ["tenant_id", "principal_id", "resource_id", "cloud_account", "region"],
    },
    "financial_services": {
        "label": "Financial services",
        "event_families": ["account_takeover", "transaction_abuse", "privileged_access_abuse", "api_abuse", "sensitive_data_access"],
        "sources": ["identity provider", "transaction platform", "API gateway", "database audit", "endpoint detection"],
        "evaluation_dimensions": ["precision", "recall", "false_positive_rate", "time_to_detect", "case_linkage"],
        "required_context": ["customer_id_tokenized", "account_id_tokenized", "transaction_id", "session_id", "device_id"],
    },
}

PLATFORM_CAPABILITY_CATALOG = [
    {"id": "ingestion", "label": "Event ingestion and normalization", "status": "implemented",
     "evaluation": ["schema_validity_pct", "duplicate_rate", "ingest_throughput_eps", "p95_ingest_latency_ms"]},
    {"id": "rule_detection", "label": "Deterministic rule detection", "status": "implemented",
     "evaluation": ["precision", "recall", "f1", "false_positive_rate", "rule_coverage_pct"]},
    {"id": "streaming", "label": "Kafka streaming", "status": "optional_integration",
     "evaluation": ["publish_success_pct", "consumer_lag", "retry_count", "dead_letter_count"]},
    {"id": "vector_rag", "label": "Vector retrieval and RAG", "status": "implemented_with_local_services",
     "evaluation": ["recall_at_k", "mrr", "citation_coverage_pct", "unsupported_claim_rate", "p95_retrieval_ms"]},
    {"id": "local_llm", "label": "Local LLM investigation", "status": "implemented_with_local_model",
     "evaluation": ["groundedness", "evidence_relevance", "p95_generation_ms", "refusal_correctness"]},
    {"id": "agent_tracing", "label": "Agent run traces", "status": "implemented",
     "evaluation": ["trace_completeness_pct", "failed_step_rate", "p95_run_duration_ms"]},
    {"id": "mcp", "label": "MCP JSON-RPC tool interface", "status": "partial",
     "evaluation": ["tool_schema_validity_pct", "authorization_denial_tests", "tool_error_rate"]},
    {"id": "a2a_acp", "label": "A2A / ACP interoperability", "status": "planned",
     "evaluation": ["agent_card_conformance_pct", "task_lifecycle_success_pct", "identity_propagation_pct"]},
    {"id": "graph", "label": "Graph analytics", "status": "partial",
     "evaluation": ["entity_resolution_precision", "relationship_precision", "query_p95_ms"]},
    {"id": "ml_models", "label": "Trained ML model registry and serving", "status": "planned",
     "evaluation": ["pr_auc", "calibration_error", "drift_score", "inference_p95_ms"]},
    {"id": "devsecops", "label": "Build, test and supply-chain controls", "status": "partial",
     "evaluation": ["test_pass_rate", "dependency_vulnerability_count", "image_scan_findings", "deployment_rollback_time"]},
]

class EventIn(BaseModel):
    event_time: datetime | None = None
    source: str = Field(default="manual", min_length=1, max_length=100)
    event_type: str = Field(min_length=1, max_length=100)
    domain: str = Field(default="cloud_saas", pattern="^(ecommerce|telecom|logistics|cloud_saas|financial_services)$")
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
    raw = dict(payload.raw or {})
    raw["_aegis_domain"] = payload.domain
    stable = json.dumps({"source": payload.source, "domain": payload.domain, "type": event_type, "time": event_time.isoformat(),
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
    matches.extend(domain_rule_matches(event))
    return matches

def domain_rule_matches(event: dict) -> list[dict]:
    """Match domain event families only when an explicit supported domain is present."""
    raw = event.get("raw") or {}
    domain = raw.get("_aegis_domain", event.get("domain", "cloud_saas"))
    if domain not in DOMAIN_CATALOG:
        return []
    event_type = event.get("event_type", "")
    if event_type not in DOMAIN_CATALOG[domain]["event_families"]:
        return []
    rule_id = "DOMAIN-" + domain.upper() + "-001"
    return [{
        "id": rule_id,
        "title": f"{DOMAIN_CATALOG[domain]['label']} suspicious activity",
        "severity": "high",
        "description": f"Event family {event_type} requires domain-aware analyst review.",
    }]


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

def _http_json(url: str, payload: dict | None = None, timeout: float = 8.0, method: str | None = None) -> dict:
    """Small stdlib JSON client for optional local integrations; never logs secrets or payloads."""
    import urllib.request
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method=method)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read(2_000_000)
    return json.loads(raw) if raw else {}


def _embed_text(text: str) -> list[float]:
    result = _http_json(OLLAMA_URL.rstrip("/") + "/api/embed", {"model": OLLAMA_EMBED_MODEL, "input": text[:12000]}, timeout=20)
    vectors = result.get("embeddings") or []
    if not vectors or not isinstance(vectors[0], list):
        raise RuntimeError("Embedding model returned no vector")
    return [float(v) for v in vectors[0]]


def _qdrant_request(path: str, payload: dict | None = None, method: str | None = None) -> dict:
    return _http_json(QDRANT_URL + path, payload, timeout=8, method=method)


def _vector_upsert_document(document: dict) -> bool:
    """Index a stored document in Qdrant using a local Ollama embedding; return False on optional-service failure."""
    try:
        vector = _embed_text(document["title"] + "\n\n" + document["content"])
        collection_path = "/collections/" + QDRANT_COLLECTION
        try:
            _qdrant_request(collection_path)
        except Exception:
            _qdrant_request(collection_path, {"vectors": {"size": len(vector), "distance": "Cosine"}}, "PUT")
        _qdrant_request(collection_path + "/points?wait=true", {"points": [{"id": document["id"], "vector": vector,
            "payload": {"document_id": document["id"], "title": document["title"], "content": document["content"][:12000], "source": document["source"]}}]}, "PUT")
        return True
    except Exception:
        return False


def _vector_search(query: str, limit: int) -> list[dict] | None:
    try:
        vector = _embed_text(query)
        result = _qdrant_request("/collections/" + QDRANT_COLLECTION + "/points/search", {"vector": vector, "limit": limit, "with_payload": True}, "POST")
        return [{"id": hit.get("payload", {}).get("document_id", str(hit.get("id"))),
                 "title": hit.get("payload", {}).get("title", "Untitled"), "content": hit.get("payload", {}).get("content", ""),
                 "source": hit.get("payload", {}).get("source", "unknown"), "score": round(float(hit.get("score", 0)), 4)}
                for hit in result.get("result", [])]
    except Exception:
        return None


def _publish_kafka_events(events: list[dict]) -> dict:
    """Best-effort optional Kafka publication; broker failures never roll back persisted PostgreSQL events."""
    if not KAFKA_ENABLED or not events:
        return {"state": "disabled", "published": 0}
    producer = None
    try:
        from kafka import KafkaProducer
        producer = KafkaProducer(bootstrap_servers=[x.strip() for x in KAFKA_BOOTSTRAP_SERVERS.split(",") if x.strip()],
            value_serializer=lambda value: json.dumps(value, default=str).encode("utf-8"), request_timeout_ms=3000, max_block_ms=3000)
        for event in events:
            producer.send(KAFKA_TOPIC, event)
        producer.flush(timeout=5)
        return {"state": "published", "published": len(events), "topic": KAFKA_TOPIC}
    except Exception as exc:
        return {"state": "error", "published": 0, "error_type": type(exc).__name__}
    finally:
        if producer is not None:
            try: producer.close(timeout=1)
            except Exception: pass


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
                             "mcp-json-rpc-tools", "integration-health-probes", "metrics", "baseline-evaluation", "agent-run-traces", "data-quality", "graph-lite", "domain-aware-detection", "domain-evaluation-smoke-tests"]}

@app.get("/api/v1/platform/catalog")
def platform_catalog():
    """Return domain coverage contracts and honest implementation/evaluation status."""
    return {
        "catalog_version": "aegis-platform-catalog-v1",
        "domains": [{"id": key, **value} for key, value in DOMAIN_CATALOG.items()],
        "capabilities": PLATFORM_CAPABILITY_CATALOG,
        "evaluation_principles": [
            "Evaluate each domain against its own labeled dataset; do not transfer scores across domains.",
            "Report false positives and false negatives alongside precision and recall.",
            "Record dataset version, sample count, time window, and model/rule version for each run.",
            "Planned or partial capabilities must not be presented as operational integrations.",
        ],
    }


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
    created, alert_ids, kafka_events = [], [], []
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
            kafka_events.append({k: event.get(k) for k in ("id", "event_time", "source", "event_type", "severity", "src_ip", "dst_ip", "username", "host", "message", "fingerprint")})
            created.append({"event_id": event["id"], "duplicate": False, "alerts": made})
    streaming = _publish_kafka_events(kafka_events)
    return {"accepted": len(created), "items": created, "alert_ids": alert_ids, "streaming": streaming}

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
    vector_indexed = _vector_upsert_document({"id": did, "title": body.title, "content": body.content, "source": body.source})
    return {"id":did,"title":body.title,"source":body.source,
            "retrieval_status":"vector_indexed" if vector_indexed else "stored_keyword_fallback",
            "note":"PostgreSQL is authoritative; vector indexing is best-effort."}

@app.post("/api/v1/knowledge/reindex")
def reindex_knowledge():
    """Best-effort reindex of existing PostgreSQL documents into Qdrant."""
    with connect() as conn:
        rows = conn.execute("SELECT id,title,content,source FROM knowledge_documents ORDER BY created_at DESC LIMIT 500").fetchall()
    indexed = 0
    failed = 0
    for did, title, content, source in rows:
        if _vector_upsert_document({"id": did, "title": title, "content": content, "source": source}):
            indexed += 1
        else:
            failed += 1
    return {"total": len(rows), "indexed": indexed, "failed": failed,
            "mode": "qdrant-vector" if indexed else "keyword-fallback",
            "note": "PostgreSQL remains authoritative. Failed vector items remain searchable through keyword fallback."}


@app.get("/api/v1/knowledge/search")
def search_knowledge(q: str = Query(min_length=2, max_length=500), limit: int = Query(default=5, ge=1, le=20)):
    vector_items = _vector_search(q, limit)
    if vector_items is not None:
        return {"query": q, "items": vector_items, "mode": "qdrant-vector", "embedding_model": OLLAMA_EMBED_MODEL,
                "note": "Local embedding retrieval; inspect evidence before acting."}
    terms=[t.lower() for t in re.findall(r"[a-zA-Z0-9_.-]+",q) if len(t)>1]
    with connect() as conn:
        rows=conn.execute("SELECT id,title,content,source FROM knowledge_documents ORDER BY created_at DESC LIMIT 500").fetchall()
    ranked=[]
    for did,title,content,source in rows:
        text=(title+" "+content).lower()
        score=sum(text.count(term) for term in terms)
        if score: ranked.append({"id":did,"title":title,"content":content[:4000],"source":source,"score":score})
    ranked.sort(key=lambda x:x["score"],reverse=True)
    return {"query":q,"items":ranked[:limit],"mode":"keyword-fallback","note":"Qdrant or the local embedding model was unavailable; results use keyword matching."}

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
    vector_evidence = _vector_search(body.question, 5)
    retrieval_mode = "qdrant-vector" if vector_evidence is not None else "keyword-fallback"
    if vector_evidence is not None:
        evidence = vector_evidence
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
        {"step": "retrieve_knowledge", "status": "ok", "evidence_count": len(evidence[:5]), "retriever": retrieval_mode},
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
              {"mode":answer["mode"], "retrieval_mode": retrieval_mode, "duration_ms": duration_ms, "evidence_count": len(evidence[:5])})
    return answer


# Versioned, deterministic baseline benchmark. These are synthetic test cases, not a
# substitute for a representative, labeled production dataset.
# v1 is frozen: do not edit its samples after results have been persisted.
DETECTION_EVAL_DATASET_V1 = [
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

# v2 deliberately includes boundary cases. Its expected errors expose current heuristic
# limitations; it is not a claim that these rules are production-ready.
DETECTION_EVAL_DATASET_V2 = [
    {"type":"authentication_failure","message":"invalid password","expected":True},
    {"type":"suspicious_process","message":"unknown unsigned binary launched","expected":True},
    {"type":"malware_detected","message":"synthetic malware signature hit","expected":True},
    {"type":"privilege_escalation","message":"unexpected privilege change","expected":True},
    {"type":"normal_activity","message":"scheduled backup completed successfully","expected":False},
    {"type":"normal_activity","message":"routine health check completed","expected":False},
    {"type":"normal_activity","message":"Security awareness report mentions mimikatz as an example","expected":False},
    {"type":"process_start","message":"unusual credential extraction utility executed","expected":True},
]
DETECTION_EVAL_DATASETS = {
    "v1": ("aegis-synthetic-detection-v1", DETECTION_EVAL_DATASET_V1),
    "v2": ("aegis-synthetic-detection-v2", DETECTION_EVAL_DATASET_V2),
}


def score_detection_dataset(dataset: list[dict]) -> dict:
    """Pure scoring function so benchmark logic can be tested without a database."""
    tp = fp = tn = fn = 0
    examples = []
    for index, sample in enumerate(dataset):
        predicted = bool(rule_matches({"event_type": sample["type"], "message": sample["message"]}))
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
    return {"sample_count": len(examples), "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "accuracy": round((tp + tn) / len(examples), 4) if examples else 0.0,
            "pass_count": sum(1 for item in examples if item["pass"]), "examples": examples}


DOMAIN_EVAL_DATASETS = {
    domain: [
        {"type": family, "message": f"Synthetic {family} signal for {domain}", "expected": True}
        for family in details["event_families"][:2]
    ] + [
        {"type": "routine_activity", "message": f"Routine successful operation for {domain}", "expected": False}
    ]
    for domain, details in DOMAIN_CATALOG.items()
}


def score_domain_dataset(domain: str, dataset: list[dict]) -> dict:
    """Score domain-aware rules without requiring database access."""
    if domain not in DOMAIN_CATALOG:
        raise ValueError(f"Unsupported domain: {domain}")
    tp = fp = tn = fn = 0
    examples = []
    for index, sample in enumerate(dataset):
        event = {"event_type": sample["type"], "message": sample["message"],
                 "raw": {"_aegis_domain": domain}}
        predicted = bool(domain_rule_matches(event))
        expected = bool(sample["expected"])
        if predicted and expected: tp += 1
        elif predicted and not expected: fp += 1
        elif not predicted and not expected: tn += 1
        else: fn += 1
        examples.append({"case": index + 1, "event_type": sample["type"],
                         "expected_detection": expected, "predicted_detection": predicted,
                         "pass": predicted == expected})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"domain": domain, "dataset_version": f"aegis-{domain}-smoke-v1",
            "evaluation_type": "synthetic-domain-rule-smoke-test", "sample_count": len(examples),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4),
            "accuracy": round((tp + tn) / len(examples), 4) if examples else 0.0,
            "pass_count": sum(1 for item in examples if item["pass"]), "examples": examples,
            "limitations": ["Three synthetic smoke cases only", "Not production detection validation",
                            "Rules require domain-specific labeled datasets before operational use"]}


@app.get("/api/v1/platform/domains/{domain}/evaluation")
def get_domain_evaluation(domain: str):
    if domain not in DOMAIN_EVAL_DATASETS:
        raise HTTPException(404, "Unknown domain; query /api/v1/platform/catalog for supported domains")
    return score_domain_dataset(domain, DOMAIN_EVAL_DATASETS[domain])


@app.post("/api/v1/platform/domains/{domain}/evaluation")
def run_domain_evaluation(domain: str):
    if domain not in DOMAIN_EVAL_DATASETS:
        raise HTTPException(404, "Unknown domain; query /api/v1/platform/catalog for supported domains")
    result = score_domain_dataset(domain, DOMAIN_EVAL_DATASETS[domain])
    run_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute("INSERT INTO evaluation_runs(id,suite,metrics) VALUES(%s,%s,%s)",
                     (run_id, f"domain-detection-{domain}", Jsonb(result)))
        audit(conn, "evaluation.completed", "evaluation", run_id,
              {"suite": f"domain-detection-{domain}", "dataset_version": result["dataset_version"],
               "sample_count": result["sample_count"], "f1": result["f1"]})
    return {"id": run_id, "suite": f"domain-detection-{domain}", **result}


@app.post("/api/v1/evaluations/run")
def run_evaluation(version: str = Query(default="v1", pattern="^v[12]$")):
    """Run and persist a named synthetic rule-baseline benchmark version."""
    dataset_version, dataset = DETECTION_EVAL_DATASETS[version]
    result = {"dataset_version": dataset_version, **score_detection_dataset(dataset),
              "limitations": ["Synthetic, hand-authored cases only", "Rule/heuristic baseline, not a trained ML model",
                              "v2 intentionally includes boundary cases to expose known heuristic errors",
                              "Do not interpret these scores as production detection quality"]}
    run_id = str(uuid.uuid4())
    with connect() as conn:
        conn.execute("INSERT INTO evaluation_runs(id,suite,metrics) VALUES(%s,%s,%s)",
                     (run_id, "detection-baseline", Jsonb(result)))
        audit(conn, "evaluation.completed", "evaluation", run_id,
              {"suite": "detection-baseline", "dataset_version": dataset_version,
               "sample_count": result["sample_count"], "f1": result["f1"]})
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



# Explainable multi-event correlations. These are investigation leads, not proof of compromise.
CORRELATION_RULES = {
    "ecommerce": {"id": "CORR-ECOM-001", "first": "account_takeover", "second": "payment_abuse", "window_minutes": 30, "entity": "username"},
    "telecom": {"id": "CORR-TEL-001", "first": "sim_swap", "second": "subscriber_account_abuse", "window_minutes": 60, "entity": "username"},
    "logistics": {"id": "CORR-LOG-001", "first": "shipment_route_deviation", "second": "warehouse_access_abuse", "window_minutes": 60, "entity": "host"},
    "cloud_saas": {"id": "CORR-CLOUD-001", "first": "credential_abuse", "second": "privilege_escalation", "window_minutes": 30, "entity": "username"},
    "financial_services": {"id": "CORR-FIN-001", "first": "account_takeover", "second": "transaction_abuse", "window_minutes": 30, "entity": "username"},
}


def correlate_events(events: list[dict]) -> list[dict]:
    """Create deterministic, explainable cross-event leads from already-normalized events."""
    normalized = []
    for event in events:
        raw = event.get("raw") or {}
        domain = raw.get("_aegis_domain", event.get("domain"))
        rule = CORRELATION_RULES.get(domain)
        if not rule:
            continue
        event_time = event.get("event_time")
        if isinstance(event_time, str):
            try:
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
            except ValueError:
                continue
        if not isinstance(event_time, datetime):
            continue
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        entity_value = event.get(rule["entity"])
        if not entity_value:
            continue
        normalized.append({**event, "_domain": domain, "_rule": rule, "_time": event_time,
                           "_entity_value": str(entity_value)})

    leads = []
    for later in normalized:
        rule = later["_rule"]
        if later.get("event_type") != rule["second"]:
            continue
        candidates = []
        for earlier in normalized:
            if earlier["_domain"] != later["_domain"] or earlier["_entity_value"] != later["_entity_value"]:
                continue
            if earlier.get("event_type") != rule["first"] or earlier["_time"] > later["_time"]:
                continue
            delta_seconds = (later["_time"] - earlier["_time"]).total_seconds()
            if delta_seconds <= rule["window_minutes"] * 60:
                candidates.append((delta_seconds, earlier))
        if not candidates:
            continue
        # Pick the closest preceding trigger so one later event does not create duplicate leads.
        delta_seconds, earlier = min(candidates, key=lambda item: item[0])
        leads.append({
            "id": f'{rule["id"]}:{earlier.get("id")}:{later.get("id")}',
            "rule_id": rule["id"], "domain": later["_domain"],
            "title": f'{later["_domain"].replace("_", " ").title()} sequence requires review',
            "severity": "high", "status": "investigation_lead",
            "entity_type": rule["entity"], "entity_value": later["_entity_value"],
            "window_minutes": rule["window_minutes"],
            "observed_interval_seconds": int(delta_seconds),
            "evidence_event_ids": [earlier.get("id"), later.get("id")],
            "event_types": [rule["first"], rule["second"]],
            "explanation": f'Observed {rule["first"]} followed by {rule["second"]} for the same {rule["entity"]} within {rule["window_minutes"]} minutes.',
            "limitations": ["Deterministic correlation heuristic", "Shared entity and event order do not prove causality or compromise"]
        })
    return sorted(leads, key=lambda item: (item["domain"], item["observed_interval_seconds"]))


@app.get("/api/v1/correlations")
def list_correlations(limit: int = Query(default=500, ge=1, le=2000),
                      domain: str | None = None):
    """Return explainable investigation leads derived from recent stored events."""
    if domain is not None and domain not in DOMAIN_CATALOG:
        raise HTTPException(400, "Unsupported domain")
    with connect() as conn:
        rows = conn.execute("""SELECT id,event_time,event_type,username,host,message,raw
            FROM (SELECT id,event_time,event_type,username,host,message,raw
                  FROM security_events ORDER BY event_time DESC LIMIT %s) recent
            ORDER BY event_time ASC""", (limit,)).fetchall()
    events = [{"id": row[0], "event_time": row[1], "event_type": row[2],
               "username": row[3], "host": row[4], "message": row[5], "raw": row[6]}
              for row in rows]
    leads = correlate_events(events)
    if domain is not None:
        leads = [lead for lead in leads if lead["domain"] == domain]
    return {"mode": "deterministic-multi-event-correlation", "events_considered": len(events),
            "lead_count": len(leads), "items": leads,
            "note": "Leads are prioritization hints for human review, not proof of malicious activity."}

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

@app.get("/api/v1/integrations")
def integration_status():
    """Probe optional services at runtime; configured containers are not assumed healthy."""
    import urllib.request
    import socket

    def http_probe(name: str, url: str, timeout: float = 1.5) -> dict:
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                body = response.read(4096)
            return {"name": name, "state": "online", "detail": f"HTTP {response.status}", "http_status": response.status}
        except urllib.error.HTTPError as exc:
            # An authentication response still proves the HTTP service is reachable.
            if exc.code in (401, 403):
                return {"name": name, "state": "reachable", "detail": f"HTTP {exc.code} (authentication required)", "http_status": exc.code}
            return {"name": name, "state": "offline", "detail": f"HTTP {exc.code}", "http_status": exc.code}
        except Exception as exc:
            return {"name": name, "state": "offline", "detail": type(exc).__name__}

    def tcp_probe(name: str, host: str, port: int, configured: bool = True) -> dict:
        if not configured:
            return {"name": name, "state": "not_configured", "detail": "Optional integration is not enabled"}
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return {"name": name, "state": "reachable", "detail": f"TCP {port} reachable"}
        except Exception as exc:
            return {"name": name, "state": "offline", "detail": type(exc).__name__}

    results = [
        http_probe("Ollama", OLLAMA_URL.rstrip("/") + "/api/tags"),
        http_probe("Qdrant", os.getenv("QDRANT_URL", "http://qdrant:6333").rstrip("/") + "/readyz"),
        tcp_probe("Kafka", os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092").split(",")[0].split(":")[0], int(os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092").split(",")[0].split(":")[-1]), KAFKA_ENABLED),
        http_probe("Neo4j HTTP", os.getenv("NEO4J_HTTP_URL", "http://neo4j:7474")),
    ]
    return {"items": results, "checked_at": datetime.now(timezone.utc).isoformat(),
            "note": "Runtime connectivity only; reachable does not imply the integration is wired into every workflow."}


MCP_TOOLS = {
    "get_overview": {"description": "Return persisted SOC counters", "inputSchema": {"type": "object", "properties": {}}},
    "search_alerts": {"description": "Search alerts by status and limit", "inputSchema": {"type": "object", "properties": {"status": {"type": ["string", "null"]}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}, "additionalProperties": False}},
    "search_knowledge": {"description": "Search stored SOC knowledge documents", "inputSchema": {"type": "object", "properties": {"q": {"type": "string", "minLength": 2}, "limit": {"type": "integer", "minimum": 1, "maximum": 20}}, "required": ["q"], "additionalProperties": False}},
    "get_graph_summary": {"description": "Return PostgreSQL-derived graph-lite associations", "inputSchema": {"type": "object", "properties": {}}},
    "get_data_quality": {"description": "Return measured event completeness", "inputSchema": {"type": "object", "properties": {}}},
}


def _mcp_call_tool(name: str, arguments: dict) -> Any:
    """Small read-only MCP-compatible tool dispatcher; no arbitrary code or response actions."""
    if name == "get_overview":
        return overview()
    if name == "search_alerts":
        status = arguments.get("status", "open")
        limit = int(arguments.get("limit", 25))
        if status not in (None, "open", "investigating", "resolved", "false_positive") or not 1 <= limit <= 100:
            raise ValueError("Invalid status or limit")
        return list_alerts(status=status, limit=limit)
    if name == "search_knowledge":
        q = arguments.get("q", "")
        limit = int(arguments.get("limit", 5))
        if not isinstance(q, str) or len(q) < 2 or len(q) > 500 or not 1 <= limit <= 20:
            raise ValueError("q must be 2-500 characters and limit 1-20")
        return search_knowledge(q=q, limit=limit)
    if name == "get_graph_summary":
        return graph_summary()
    if name == "get_data_quality":
        return data_quality()
    raise KeyError(name)


@app.post("/mcp")
def mcp_json_rpc(payload: dict):
    """MCP JSON-RPC endpoint for initialization, tool discovery and bounded read-only calls."""
    request_id = payload.get("id")
    method = payload.get("method")
    params = payload.get("params") or {}
    def error(code: int, message: str):
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    if payload.get("jsonrpc") != "2.0" or not isinstance(method, str):
        return error(-32600, "Invalid JSON-RPC request")
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "protocolVersion": params.get("protocolVersion", "2024-11-05"),
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "aegis-ai-soc", "version": app.version}}}
    if method == "notifications/initialized":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": [
            {"name": name, **definition} for name, definition in MCP_TOOLS.items()]}}
    if method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if name not in MCP_TOOLS or not isinstance(arguments, dict):
            return error(-32602, "Unknown tool or invalid arguments")
        try:
            result = _mcp_call_tool(name, arguments)
            with connect() as conn:
                audit(conn, "mcp.tool_called", "tool", name, {"argument_keys": sorted(arguments.keys())})
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [
                {"type": "text", "text": json.dumps(result, default=str)}], "isError": False}}
        except KeyError:
            return error(-32602, "Unknown tool")
        except (ValueError, TypeError) as exc:
            return error(-32602, str(exc))
        except Exception:
            return {"jsonrpc": "2.0", "id": request_id, "result": {"content": [
                {"type": "text", "text": "Tool execution failed; inspect server logs."}], "isError": True}}
    if method.startswith("notifications/"):
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    return error(-32601, "Method not found")


@app.get("/api/v1/audit")
def audit_entries(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as conn:
        rows=conn.execute("SELECT id,action,entity_type,entity_id,details,created_at FROM audit_log ORDER BY created_at DESC LIMIT %s",(limit,)).fetchall()
    keys=["id","action","entity_type","entity_id","details","created_at"]
    return {"items":[dict(zip(keys,r)) for r in rows]}
