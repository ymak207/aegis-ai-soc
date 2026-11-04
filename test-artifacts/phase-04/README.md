# Phase 04 — ML anomaly baseline acceptance

## Scope

Validates the existing experimental IsolationForest API (`POST /api/v1/ml/anomaly/run`) and run history. It does **not** claim supervised model quality, production detection efficacy, or maliciousness probability.

## Contents

- `data/ml_anomaly_events.json`: 40 synthetic Cloud/SaaS events; 32 routine baseline examples and 8 variants.
- `scripts/run_ml_acceptance.py`: creates a uniquely tagged batch, runs the model twice, validates score/label/report shape, checks repeatability, persistence and audit.
- `scripts/cleanup_ml.sh`: removes only event and ML-run IDs from the report; audit records remain.
- `results/`: reserved for the generated acceptance report.

## Run

Extract the archive into the repository root so it creates `test-artifacts/phase-04/`.

```bash
cd ~/projects/aegis-ai-soc
python3 test-artifacts/phase-04/scripts/run_ml_acceptance.py
```

The API must be reachable at `http://127.0.0.1:8000`, and scikit-learn must be installed in the API image. The runner creates 40 events and two persisted ML runs. It deliberately does not assert that a particular synthetic attack is detected: this is an unsupervised baseline trained on the same selected population, not a labeled holdout evaluation.

Inspect the generated report. Then clean up:

```bash
bash test-artifacts/phase-04/scripts/cleanup_ml.sh
```

Type `DELETE-PHASE-04-ML` when prompted. The cleanup script supports a partial report if a test fails after creating data.

## Acceptance checks

- Fixture contains 40 records; API rejects `limit=19` with HTTP 422.
- 40 unique events are accepted without duplicate replay.
- Two IsolationForest runs return the expected model/version/training mode.
- Each run uses 40 samples and returns 25 unique top-scored records.
- Scores are in [0,1], labels are from the documented set, and limitations are disclosed.
- Fixed random seed yields matching top-event ordering and candidate counts across runs.
- Both ML runs persist and each has an audit entry.

The fixture is synthetic and should not be used to calculate precision, recall, F1, PR-AUC, calibration, or production quality.
