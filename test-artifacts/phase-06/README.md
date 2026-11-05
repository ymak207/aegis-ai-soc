# Phase 06 — Detection Engineering Quality

## Scope
Tests all 25 configured domain event families, the four general rule groups, the substring command-line heuristic (including known educational-text false positives), alert persistence/rule severity, exact replay idempotency, and optional ingestion throughput at 20/100/250/500 events.

This is synthetic contract testing, not production detection validation. Domain-family matches currently create generic high-severity analyst-review alerts, not family-specific detections.

## Run from repository root
Prerequisites: API reachable at `http://localhost:8000`; Python 3.10+ and `requests`.
Set `AEGIS_API_URL` if needed.

1. `python3 -m pip install requests` (only if missing)
2. `python3 test-artifacts/phase-06/scripts/run_detection_acceptance.py`
3. Optional: `python3 test-artifacts/phase-06/scripts/run_detection_performance.py`
4. Review `test-artifacts/phase-06/results/*.json`
5. Cleanup: `bash test-artifacts/phase-06/scripts/cleanup_detection.sh`

Events use source `phase06-detection` and `raw.phase06_run` markers. Cleanup is scoped to these records, relies on the event-alert FK cascade, and retains audit history. The cleanup script prompts for `DELETE-PHASE-06`.

The educational `mimikatz` and `powershell -enc` examples are expected to match BEHAVIOR-001 under the current substring heuristic; they are recorded as known false positives rather than counted as successful detections. Performance figures are single-run observations without an SLA claim.
