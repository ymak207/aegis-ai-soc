# AEGIS AI SOC

Self-hosted defensive Security Operations Center proof of concept. The core stack is FastAPI, React/TypeScript, PostgreSQL and Redis. Optional profiles add ClickHouse analytics, Qdrant vector search, Ollama local inference, MinIO object storage, and Prometheus/Grafana.

## Application lifecycle scripts

From the repository root on Linux:

```bash
./scripts/start.sh       # validate Compose, build and start core services, wait for readiness
./scripts/status.sh      # show container status
./scripts/status.sh --wait # show status and verify API/frontend readiness
./scripts/stop.sh        # stop services; preserve data volumes
./scripts/reset.sh       # interactive destructive reset; requires typing RESET-AEGIS
```

`./scripts/reset.sh` deletes Compose-managed volumes (PostgreSQL, Redis and any optional profile data). It preserves source code and `.env`. Do not use it unless you intend to erase persisted application data. `./scripts/reset.sh --yes` skips the confirmation and should be used only deliberately.

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

## UI workspaces

The web console includes Command center, Detection & response, Intel & knowledge, and Stack & evaluation workspaces. The Stack & evaluation page shows live core dependency checks and actual Prometheus-format counters. Supervised ML model quality, agent task success, RAG recall and graph quality are explicitly marked unmeasured until repeatable labeled benchmarks and integrated runtimes are added; the UI does not invent quality scores.

The frontend's Vite proxy forwards `/api`, `/health` and `/metrics` to the API container. Ports remain bound to loopback by default.

## Evaluation, agent traces and graph-lite (baseline)

- `POST /api/v1/evaluations/run` runs the versioned `aegis-synthetic-detection-v1` rule benchmark and persists precision, recall, F1, accuracy, confusion counts and per-case outcomes.
- `GET /api/v1/evaluations/results` returns saved benchmark runs.
- `GET /api/v1/agents/runs` returns persisted investigation-agent traces, duration and evidence counts. Investigation requests store a trace whether Ollama succeeds or falls back.
- `GET /api/v1/data/quality` reports completeness for source IP, host and username fields in stored events.
- `GET /api/v1/graph/summary` derives event-type/host/user associations from PostgreSQL. It is graph-lite and does not query Neo4j or infer causality.
- The Stack & evaluation page can run the benchmark and shows measured event quality, graph-lite counts and recent investigation traces.

The synthetic detection benchmark is a software regression signal, **not** a supervised ML model evaluation and not a production-quality claim. Release 0.3 adds an experimental unsupervised IsolationForest anomaly-scoring baseline; its scores are triage signals, not maliciousness probabilities. Real ML requires representative labeled data and a versioned train/test split. Retrieval remains keyword-based until embedding generation, vector storage, chunking and retrieval evaluation are connected. The MCP endpoint remains a catalog, not a full MCP transport; A2A/ACP are not implemented. Optional Kafka, Neo4j, Qdrant, ClickHouse, MinIO and Ollama profiles are not automatically wired into the event pipeline merely by starting their containers.

## Important limitations

This is a development POC, not a production-ready SOC: authentication/RBAC, TLS, secrets management, external log collectors, Kafka-backed ingestion wiring, Sigma rule compatibility, vector embedding ingestion, a full MCP transport, A2A/ACP protocol implementations, and production hardening remain future work. Kafka and Neo4j are optional infrastructure profiles and are not yet wired into the core ingestion path. The included detections are illustrative heuristics, not a replacement for tested detection content. Review all alerts and AI output with a human analyst.


## Release hardening patch (2026-10-26)

This patch adds defense-in-depth HTTP response headers and an early request-body size guard.
`MAX_REQUEST_BYTES` defaults to 10 MiB and can be changed in `.env`; oversized requests
with a declared `Content-Length` are rejected with HTTP 413. API responses are marked
`Cache-Control: no-store`, and include `X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, and `Permissions-Policy`. Regression tests cover these controls.

**Important security boundary:** these headers and the size guard are not authentication,
authorization, TLS, tenant isolation, or a WAF. Keep AEGIS behind a private network or
authenticated reverse proxy. Do not expose API, PostgreSQL, Redis, Ollama, Qdrant, Kafka,
or other optional service ports directly to the public internet. Rotate all sample/default
credentials before any shared or non-local deployment. Browser-side API keys are not a
safe substitute for server-side authentication.

## Release 0.3 — Lab and Sources

### AEGIS Lab

- `GET /api/v1/lab/scenarios` returns the versioned scenario catalog across e-commerce, telecom, logistics, cloud/SaaS and financial services. `GET /api/v1/lab/export?format=jsonl|csv|json` exports recent synthetic Lab/simulation events for offline import testing.
- `POST /api/v1/lab/run` runs `domain_smoke`, `benign_baseline`, `mixed_suite`, or `all`; accepts `domain` (`all` or one domain) and `scale` (1–20). Results are persisted in `lab_runs` and audited. Mixed/all suites also execute the existing two-event correlation simulator for each selected domain.
- Synthetic events use documentation-only TEST-NET addresses and are persisted in the same database and detection path as normal events. Runs are not destructive and will add events/alerts/correlation evidence to your environment.
- The suite validates deterministic rule and correlation behavior only. It does not emulate a complete attacker, prove production detection quality, or evaluate LLM answer quality.

### Sources and imports

- `GET/POST /api/v1/sources` lists/registers source metadata; `PATCH /api/v1/sources/{id}` updates an operator-managed status. Source status is not a live connectivity probe.
- `POST /api/v1/sources/import` accepts `source_name`, `domain`, `format` (`json`, `jsonl`, `ndjson`, `csv`, `text`, `syslog`), `content`, and optional `mapping` (`canonical_field` to input field). Requests are limited to 5 MB and 500 records and pass through the existing event normalization/detection path.
- Text/syslog parsing is deliberately conservative: it recognizes a small set of authentication, privilege, suspicious-process and malware phrases, preserving raw lines. Unknown lines become `log_message`; vendor-specific parsers are still needed.
- File/manual source types have functional import paths. Webhook, REST API, syslog listener and Kafka consumer source types are registry/onboarding metadata only until their connector runtimes are implemented. Do not mark them connected based only on registry status.
- Source `config` rejects obvious credential-bearing keys. Store real credentials in deployment secrets, never in source metadata or browser code.

### Release limitations

This release adds the Lab and Sources experience and source/file import path; it does not turn every optional Compose service into an integrated runtime. Supervised ML/model registry/drift monitoring, live vendor connectors, authentication/RBAC, tenant isolation, full Sigma support, full packet-capture analysis, and production-ready multi-agent orchestration remain separate engineering work. Keep the application private and analyst-reviewed.

### Local anomaly-scoring baseline

- `POST /api/v1/ml/anomaly/run?limit=1000` fits a scikit-learn IsolationForest on recent stored event features (requires at least 20 events) and persists a versioned run report.
- `GET /api/v1/ml/anomaly/runs` lists previous reports. The Lab workspace exposes the action and top scored events.
- This is a real unsupervised ML baseline, but it is trained on the selected current event population; it is not a supervised classifier, does not provide maliciousness probabilities, and has no durable fitted artifact or drift monitoring yet. Treat results as analyst prioritization only. For meaningful evaluation, use representative telemetry and a separate labeled holdout set.
