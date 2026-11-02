# Phase 03 — B3 Detection and Correlation Acceptance

This is the next uncovered backend acceptance slice. It does NOT repeat:
- Phase 01 OpenAPI / 17 GET baseline checks
- Phase 02 JSON, JSONL, CSV, syslog import tests
- B1 39 unit tests
- B2 indicator, case, knowledge, investigation and audit workflow tests

## Exact scope
1. Ingest 11 synthetic events through `POST /api/v1/events/batch`.
2. Assert exact detection rule IDs and severity for authentication failure, suspicious process + behavior heuristic overlap, domain events, and benign negative.
3. Replay one identical event and verify idempotency: same event ID, duplicate=true, no new alerts.
4. Read persisted events and alerts back through APIs.
5. Verify cloud SaaS correlation `CORR-CLOUD-001`, exact evidence event IDs and 600-second interval.
6. Verify no lead for different entity, reversed order, or 31-minute interval.

The correlation endpoint computes leads dynamically from stored events; it does not persist a separate correlation row. This is explicitly tested as a read-after-ingest behavior.

## Dataset
`data/detection_correlation_events.json` contains the complete 11-event fixture and expected rule IDs. All IPs are RFC 5737 TEST-NET addresses. The data is synthetic and does not contact external systems.

## Run
From repository root:
```bash
python3 test-artifacts/phase-03/scripts/run_b3_detection_correlation.py
```
Expected: 7 checks pass and `B3 ACCEPTANCE PASSED`.
Report: `test-artifacts/phase-03/results/b3_acceptance_report.json`

If it fails, do not rerun blindly and do not clean up. Send the terminal output and report. The report records IDs created before failure.

## Cleanup
Only after a PASS and after reviewing the report:
```bash
bash test-artifacts/phase-03/scripts/cleanup_b3.sh
```
Type `DELETE-B3-TEST-DATA` when prompted. This deletes only the 11 exact event IDs in the report. Associated alerts are removed by the event foreign-key cascade. Audit rows are retained.

## Important
This acceptance tests the currently implemented deterministic rules and correlation logic only. It does not establish production detection efficacy, domain coverage beyond the tested cloud SaaS sequence, or causality/compromise.
