# AEGIS Backend Acceptance Pack 03 (B2)

## Scope
This pack tests only uncovered database-backed workflows:
- threat indicator create/read and event enrichment
- alert persistence from an indicator match
- case create/update/timeline
- knowledge document persistence and retrieval
- investigation response and agent-run persistence
- audit records for all created entities

It deliberately does NOT rerun Phase 01 GET smoke checks, Phase 02 file-format imports, or the 39 backend unit tests.

## Prerequisites
- Run from `~/projects/aegis-ai-soc`.
- API and PostgreSQL/Redis services are already running.
- Python 3.10+ on the VM; runner uses only the standard library.
- The test uses TEST-NET-2 address `198.51.100.77`, not a routable external IOC.

## Install the pack
Extract the supplied ZIP into the repository root so its `test-artifacts/phase-03/` directory merges with the existing `test-artifacts/` directory.

If using Python (works without `unzip`):
```bash
python3 - <<'PY'
import zipfile
zipfile.ZipFile('/path/to/aegis-backend-acceptance-pack-03.zip').extractall('.')
PY
```

## Execute
```bash
cd ~/projects/aegis-ai-soc
python3 test-artifacts/phase-03/scripts/run_acceptance.py
```
Expected: 6 named checks PASS and `B2 ACCEPTANCE PASSED`. The JSON report is written to `test-artifacts/phase-03/results/acceptance_report.json`.

The knowledge layer can report `vector_indexed` or `stored_keyword_fallback`. Both are supported because PostgreSQL is authoritative and vector indexing is best-effort. Investigation may use local Ollama or the deterministic evidence fallback. The report records which mode was exercised.

## Cleanup
Only after reviewing the report:
```bash
bash test-artifacts/phase-03/scripts/cleanup.sh
```
The script requires the exact confirmation `DELETE-B2-TEST-DATA`. It deletes only the IDs in this pack's report. Audit rows are intentionally retained. Events are deleted last so their alert rows cascade; cases cascade to their timeline entries.

## Safety
- Do not run cleanup if the report is missing, marker differs, or status is FAIL.
- Do not run the test multiple times without cleaning the previous run; indicator values are unique and repeated requests upsert.
- Preserve `acceptance_report.json` as evidence after cleanup.
