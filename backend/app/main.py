import os
from datetime import datetime, timezone

import psycopg
import redis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AEGIS AI SOC API", version="0.1.0", description="Security operations, event analysis, and investigation platform.")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["Content-Type", "Authorization"])
DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL = os.getenv("REDIS_URL", "")

@app.get("/health/live", tags=["health"])
def liveness():
    return {"status": "alive", "service": "aegis-api"}

@app.get("/health/ready", tags=["health"])
def readiness():
    checks = {}
    try:
        with psycopg.connect(DATABASE_URL, connect_timeout=3) as conn:
            conn.execute("SELECT 1")
        checks["postgres"] = "ok"
    except Exception:
        checks["postgres"] = "unavailable"
    try:
        redis.Redis.from_url(REDIS_URL, socket_connect_timeout=3).ping()
        checks["redis"] = "ok"
    except Exception:
        checks["redis"] = "unavailable"
    ready = all(value == "ok" for value in checks.values())
    return {"status": "ready" if ready else "degraded", "checks": checks}

@app.get("/api/v1", tags=["system"])
def system_info():
    return {"name": "AEGIS AI SOC", "version": app.version, "status": "operational", "utc_time": datetime.now(timezone.utc).isoformat(), "capabilities": ["security-event-ingestion", "detection-and-alerts", "investigation-workflows", "threat-intelligence", "ai-assisted-analysis"]}
