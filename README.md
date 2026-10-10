# AEGIS AI SOC

Self-hosted defensive Security Operations Center proof of concept. The core stack is FastAPI, React/TypeScript, PostgreSQL and Redis. Optional profiles add ClickHouse analytics, Qdrant vector search, Ollama local inference, MinIO object storage, and Prometheus/Grafana.

## Core startup

```bash
cp .env.example .env
# Change every development password in .env before exposing or sharing the deployment.
sudo docker compose up -d --build
./scripts/verify-app.sh
```

The API and frontend ports are bound to loopback by default. Use SSH port forwarding to access them remotely; do not expose the development services directly to the public internet.

## Optional profiles

```bash
sudo docker compose --profile analytics up -d clickhouse
sudo docker compose --profile ai up -d qdrant ollama
sudo docker compose --profile data up -d minio
sudo docker compose --profile observability up -d prometheus grafana
sudo docker compose --profile streaming up -d kafka
sudo docker compose --profile graph up -d neo4j
```

For CPU-only local inference, start Ollama and pull a small model from inside its container:

```bash
sudo docker compose exec ollama ollama pull qwen2.5:3b
```

Model weights can consume several gigabytes. Do not enable every profile at once on the 32 GiB / 100 GB VM; monitor memory and disk.

## Implemented API baseline

- `POST /api/v1/events` and `/api/v1/events/batch`: normalized event ingestion and rule-based detections.
- `GET /api/v1/events`, `/api/v1/alerts`, `/api/v1/overview`: event/alert queue and metrics.
- `PATCH /api/v1/alerts/{id}`: alert status workflow.
- `POST/GET/PATCH /api/v1/cases`, `GET /api/v1/cases/{id}/timeline`: cases and analyst notes.
- `POST/GET /api/v1/intel/indicators`: manual threat indicator management and event enrichment.
- `POST /api/v1/knowledge/documents`, `GET /api/v1/knowledge/search`: local document storage and keyword retrieval.
- `POST /api/v1/investigations`: evidence-first investigation; uses Ollama if available, otherwise returns a deterministic fallback.
- `GET /api/v1/mcp/tools`: internal tool catalog, not a full MCP protocol server.
- `GET /metrics`: Prometheus-format counters.

## Important limitations

This is a development POC, not a production-ready SOC: authentication/RBAC, TLS, secrets management, external log collectors, Kafka-backed ingestion wiring, Sigma rule compatibility, vector embedding ingestion, a full MCP transport, A2A/ACP protocol implementations, and production hardening remain future work. Kafka and Neo4j are optional infrastructure profiles and are not yet wired into the core ingestion path. The included detections are illustrative heuristics, not a replacement for tested detection content. Review all alerts and AI output with a human analyst.
