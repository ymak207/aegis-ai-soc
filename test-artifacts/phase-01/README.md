# AEGIS Acceptance Pack 01 — Contract & Baseline

This pack is read-only. It discovers the deployed API's actual OpenAPI request schemas and captures baseline GET responses. It does not create or modify records.

## Run on the AEGIS VM

Copy this folder into `~/projects/aegis-ai-soc/test-artifacts/phase-01/`, then run:

```bash
cd ~/projects/aegis-ai-soc
python3 test-artifacts/phase-01/scripts/inspect_contract.py
python3 test-artifacts/phase-01/scripts/baseline_readonly.py
```

Both scripts use only Python's standard library. Default API: `http://127.0.0.1:8000`. Set `AEGIS_BASE_URL` to override.

Results are saved under `test-artifacts/phase-01/results/`:
- `openapi.json`
- `request_schemas.json`
- `baseline_get_results.json`

No ingestion fixtures or POST runner are included yet: the captured output contained unresolved `$ref` pointers, not the actual field definitions for `EventIn`, `SourceIn`, and `ImportIn`. We should build JSON/JSONL/CSV/syslog test data against those exact schemas, rather than guessing payload formats or writing untraceable records.
