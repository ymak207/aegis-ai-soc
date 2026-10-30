# AEGIS Acceptance Pack 02 — Sources and File Ingestion

This pack tests the deployed AEGIS 0.3.0 API using the request contracts and implementation supplied by the user.

## Safety and side effects

The runner CREATES one uniquely named `file_import` source and imports synthetic events. It does not update or delete existing records. It creates events, rule alerts (where current rules match), and audit entries. The unique marker is `AEGIS-ACCEPTANCE-PACK-02`.

The runner also submits two negative tests:
- malformed JSON import (expected HTTP 422)
- source configuration containing `api_key` (expected HTTP 422)

After reviewing `results/acceptance_report.json`, optional cleanup can delete only marker-tagged events and the dedicated source. Alert rows cascade from deleted events. Audit entries are intentionally retained as an audit trail.

## Install and run

Extract the ZIP into the repository root, so the folder is `test-artifacts/phase-02/`.

```bash
cd ~/projects/aegis-ai-soc
python3 test-artifacts/phase-02/scripts/run_acceptance.py
```

The runner uses Python's standard library and calls `http://127.0.0.1:8000` by default. Override with `AEGIS_BASE_URL`.

## Data files

- `data/events.json`: two canonical events (one AUTH rule positive, one benign negative)
- `data/events.jsonl`: two alternate-field events with explicit mapping
- `data/events.csv`: two alternate-field CSV rows with explicit mapping
- `data/events.syslog`: three raw syslog-style lines; parser classifies recognizable patterns and preserves each raw line

All IP addresses are documentation-only TEST-NET-1 addresses (192.0.2.0/24).

## Cleanup

After reviewing the report:

```bash
bash test-artifacts/phase-02/scripts/cleanup_tagged_data.sh
```

The script requires typing `DELETE-TEST-DATA`. It deletes only events matching the unique marker/source and the dedicated source registry entry. PostgreSQL's event-to-alert foreign key cascades alert deletion. Audit rows are retained intentionally.

## Interpretation limitations discovered in the supplied source

- The text and syslog formats share one conservative keyword parser; this is not a full RFC 3164/5424 parser.
- JSON/JSONL/CSV rows are validated as a complete batch before `ingest_batch` is called, so parse/schema validation errors should reject before event writes.
- `ingest_batch` counts duplicate input rows in `accepted`; duplicate rows return `duplicate: true` and no new alerts. Therefore `accepted` means processed input items, not necessarily newly inserted events.
- The current event list response does not expose `raw`, so the runner validates read-after-write by unique marker in message. Full raw-field verification requires direct DB inspection.
- Rule coverage is intentionally narrow. `authentication_failure`, `privilege_escalation`, `suspicious_process`, `malware_detected`, and `threat_indicator_match` have current rule entries. Domain-specific scenario names such as `sim_swap`, `payment_abuse`, and `data_exfiltration` are not automatically covered by the four visible generic rules.
- The source's `status` is updated to `ingesting` only if a source with matching name and domain exists.
- A failed post-ingestion source status/audit update could occur after events have already committed; import is not a single transaction across both operations.

Do not interpret a passing synthetic test as production detection efficacy.
