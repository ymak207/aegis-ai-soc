# Phase 05 — ML ranking quality, sparse telemetry and operational behavior

## Purpose

Phase 04 established that the IsolationForest endpoint executes, scores, persists and audits successfully. Phase 05 adds a labeled synthetic diagnostic fixture and measures what the current API actually exposes.

This is an **exploratory quality and operational test**, not a production efficacy certification.

## Contents

- `data/ml_quality_events.json`: 500 deterministic synthetic records:
  - 400 routine records
  - 50 benign records with missing source IP, username and host
  - 50 rare synthetic outlier-like records
- `scripts/run_ml_quality.py`: ingestion, ranking diagnostics at 20/120/500 events, concurrent execution, persistence and audit checks.
- `scripts/cleanup_ml_quality.sh`: deletes only event and ML-run UUIDs recorded in the generated report. Audit rows are retained.
- `results/`: generated report location.

## Preconditions

- Run from the AEGIS repository root.
- Docker Compose API and PostgreSQL services must be healthy.
- API must be reachable at `http://127.0.0.1:8000`.
- Python 3 standard library only is required on the VM; no host-side pip installation.

## Install into the existing test-artifacts tree

The ZIP has a single `phase-05/` root. From the repository root, extract it under `test-artifacts/`:

```bash
cd ~/projects/aegis-ai-soc
python3 - <<'PY'
import zipfile
with zipfile.ZipFile('/path/to/aegis-phase-05-ml-quality.zip') as z:
    z.extractall('test-artifacts')
PY
```

Replace `/path/to/` with the actual ZIP location. This creates only `test-artifacts/phase-05/`; it does not create a new root-level test directory.

## Run

```bash
python3 test-artifacts/phase-05/scripts/run_ml_quality.py
```

The runner:
1. Confirms the fixture version/count and the API's minimum sample validation.
2. Ingests one batch of 500 tagged records.
3. Runs the model at sample sizes 20, 120 and 500.
4. Runs two concurrent 500-event model requests.
5. Verifies all five run records and audit records.

The runner records response time, candidate count, top-25 label composition, precision@K and recall@K. The API returns only the top 25 scored records, not all per-event scores. Therefore full-dataset ROC-AUC, PR-AUC, calibration and threshold optimization are intentionally not calculated.

The quality metrics are diagnostic observations, not hard pass thresholds. A successful acceptance means the test executed and the evidence was collected; it does not mean the model is accurate enough for production.

## Cleanup

After reviewing `results/ml_quality_report.json`:

```bash
bash test-artifacts/phase-05/scripts/cleanup_ml_quality.sh
```

Type exactly:

```text
DELETE-PHASE-05-ML-QUALITY
```

Cleanup removes only the recorded Phase 05 ML run and event IDs. It retains audit history. Do not edit the report's `marker` or `created_ids` before cleanup.

## Interpretation cautions

- `precision_at_k` and `recall_at_k` use only the returned top-K list, where K is at most 25.
- `recall_at_k` is a lower-bound ranking observation relative to the known positive count because records below rank 25 are not returned.
- `benign_sparse` ranking measures sensitivity to missing telemetry fields; it is not a real-world false-positive rate.
- The dataset intentionally makes rare event types and rare IP prefixes easy to distinguish. Strong ranking here can overstate performance on realistic adversarial or drifted data.
- The endpoint fits IsolationForest on the same selected population. This is not a train/test split or an independent holdout evaluation.
