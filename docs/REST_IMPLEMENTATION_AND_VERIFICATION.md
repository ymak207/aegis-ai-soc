# AEGIS AI SOC: vector retrieval and optional streaming verification

## Scope and honest status

This change adds optional local embedding/vector retrieval using Ollama and Qdrant, document reindexing, and best-effort Kafka event publication. PostgreSQL remains authoritative. Keyword retrieval remains the fallback. It does not implement a trained ML model, Neo4j graph analytics, A2A/ACP orchestration, or automated response actions.

## Apply safely

From the repository root:

```bash
git status --short
git log -1 --oneline
git apply --check aegis-ai-soc-rest-implementation.patch
git apply aegis-ai-soc-rest-implementation.patch
git diff --check
```

Stop if `git apply --check` fails. Do not force it or reset uncommitted work.

## Bash verification

```bash
sudo docker compose config -q
sudo docker compose build api frontend
sudo docker compose run --rm --no-deps api python -m py_compile /app/app/main.py
sudo docker compose run --rm --no-deps api python -m pytest -q /app/tests
sudo docker compose run --rm --no-deps frontend npm test
sudo docker compose run --rm --no-deps frontend npm run build
./scripts/start.sh
./scripts/verify-app.sh
```

Expected: all backend tests pass; TypeScript check and Vite production build succeed; `verify-app.sh` ends with `APPLICATION VERIFICATION PASSED`.

## Add a real sample document from this repository

Use the included file `docs/sample-data/privileged-account-authentication-runbook.md`. The UI's document form accepts plain text; paste the file's contents into the Content field and use title `Privileged account authentication failures runbook`. Source can remain `analyst-console`.

Alternatively, from the repository root, submit the same sample through the API (this uses the actual file, no hand-crafted document payload):

```bash
python3 - <<'PY' | curl --noproxy '*' -sS -X POST http://127.0.0.1:8000/api/v1/knowledge/documents -H 'Content-Type: application/json' --data-binary @-
import json
from pathlib import Path
print(json.dumps({
  "title": "Privileged account authentication failures runbook",
  "content": Path("docs/sample-data/privileged-account-authentication-runbook.md").read_text(),
  "source": "verification-runbook"
}))
PY
```

## Verify optional vector RAG

Start optional AI services and pull the local models:

```bash
sudo docker compose --profile ai up -d qdrant ollama
sudo docker compose exec ollama ollama pull qwen2.5:3b
sudo docker compose exec ollama ollama pull nomic-embed-text
sudo docker compose up -d --build api frontend
```

Check integration status:

```bash
curl --noproxy '*' -sS http://127.0.0.1:8000/api/v1/integrations
```

Reindex stored documents:

```bash
curl --noproxy '*' -sS -X POST http://127.0.0.1:8000/api/v1/knowledge/reindex
```

Search the sample runbook:

```bash
curl --noproxy '*' -sS 'http://127.0.0.1:8000/api/v1/knowledge/search?q=privileged%20account%20repeated%20authentication&limit=5'
```

When Qdrant and Ollama embeddings work, the response mode should be `qdrant-vector`. If either is unavailable, `keyword-fallback` is an expected degraded mode, not a successful vector test. Confirm the returned result title matches the sample runbook. Run an investigation from the UI and inspect its evidence and trace for the selected retriever.

## Frontend checks

1. Open the forwarded frontend URL (normally `http://127.0.0.1:5173`).
2. Open **Intel & knowledge**; add the supplied runbook using the title above and its full content.
3. Click **Reindex vector store**; note total, indexed and failed counts.
4. Search for `privileged account repeated authentication`; confirm the sample runbook appears.
5. Open **Detection & response**, submit a synthetic authentication-failure event, and run the investigation assistant. Confirm its evidence is from stored documents and recommendations remain advisory.
6. Open **Stack & evaluation**, refresh diagnostics and confirm Ollama/Qdrant statuses match reality.
7. Stop optional AI services and repeat the search. The API should degrade to keyword fallback rather than fail the whole application.

## Optional Kafka checks

Only if explicitly testing streaming, add to `.env` (do not replace existing secrets):

```dotenv
KAFKA_ENABLED=true
KAFKA_BOOTSTRAP_SERVERS=kafka:9092
KAFKA_TOPIC=aegis.security.events
```

Then run:

```bash
sudo docker compose --profile streaming up -d kafka
sudo docker compose --profile streaming up -d --build api
curl --noproxy '*' -sS -X POST http://127.0.0.1:8000/api/v1/events/batch -H 'Content-Type: application/json' -d '{"events":[{"event_type":"authentication_failure","source":"verification","severity":"medium","src_ip":"198.51.100.23","username":"synthetic-user","message":"Verification-only synthetic login failure"}]}'
```

Inspect the response's `streaming` object. `published` confirms publication; `disabled` means the flag is off; `error` means the broker publish failed. PostgreSQL persistence is independent of the best-effort publish result.

## Final evidence to capture

- Output of backend pytest.
- Output of frontend `npm test` and `npm run build`.
- Final `./scripts/verify-app.sh` result.
- Integration status JSON.
- Reindex JSON and search response showing the mode and sample title.
- If Kafka was tested, the batch event response including `streaming`.
