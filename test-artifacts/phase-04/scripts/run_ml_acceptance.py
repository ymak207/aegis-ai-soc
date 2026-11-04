#!/usr/bin/env python3
"""Phase 04 ML anomaly baseline acceptance; creates scoped synthetic events and two persisted runs."""
import json, time, urllib.error, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'data/ml_anomaly_events.json'
RESULTS = ROOT / 'results'
REPORT = RESULTS / 'ml_acceptance_report.json'
BASE = 'http://127.0.0.1:8000'
checks, event_ids, run_ids, runs = [], [], [], []


def save_report(status='IN_PROGRESS'):
    report = {
        'marker': 'AEGIS-ML-20261102', 'dataset_version': fixture.get('dataset_version'),
        'status': status, 'checks': checks,
        'created_ids': {'events': event_ids, 'ml_runs': run_ids}, 'runs': runs,
        'notes': [
            'This validates IsolationForest execution, score contract, persistence, audit and repeatability only.',
            'The fixture is synthetic and is not a labeled holdout; no precision, recall, PR-AUC or production detection-quality claim is made.',
            'Anomaly scores are relative triage signals, not maliciousness probabilities.'
        ]}
    REPORT.write_text(json.dumps(report, indent=2, default=str) + '\n')


def request(path, method='GET', payload=None):
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(BASE + path, data=body,
        headers={'Content-Type': 'application/json'}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors='replace')
        try: data = json.loads(raw)
        except Exception: data = {'raw': raw}
        return exc.code, data


def check(name, condition, details=None):
    checks.append({'name': name, 'status': 'PASS' if condition else 'FAIL', 'details': details or {}})
    print(('PASS' if condition else 'FAIL') + ': ' + name)
    save_report()
    if not condition:
        raise AssertionError(f'{name}: {details}')


RESULTS.mkdir(parents=True, exist_ok=True)
fixture = json.loads(DATA.read_text())
records = fixture['events']
try:
    check('fixture_version_and_count', fixture['dataset_version'] == 'aegis-ml-anomaly-fixture-v1' and len(records) == 40,
          {'dataset_version': fixture.get('dataset_version'), 'event_count': len(records)})

    status, invalid = request('/api/v1/ml/anomaly/run?limit=19', 'POST')
    check('reject_limit_below_20', status == 422, {'http_status': status, 'response': invalid})

    now = datetime.now(timezone.utc).replace(microsecond=0)
    payload_events = []
    for index, item in enumerate(records):
        event = {k: v for k, v in item.items() if k != 'case'}
        event['event_time'] = (now + timedelta(seconds=index)).isoformat().replace('+00:00', 'Z')
        event['raw'] = {'acceptance_marker': fixture['marker'], 'fixture_case': item['case'], 'fixture_index': index}
        payload_events.append(event)

    status, ingestion = request('/api/v1/events/batch', 'POST', {'events': payload_events})
    items = ingestion.get('items', [])
    event_ids.extend(x.get('event_id') for x in items if x.get('event_id'))
    check('ingest_40_scoped_events', status == 200 and ingestion.get('accepted') == 40 and len(event_ids) == 40,
          {'http_status': status, 'accepted': ingestion.get('accepted'), 'returned_ids': len(event_ids)})
    check('no_duplicate_ingestion', all(not x.get('duplicate', False) for x in items),
          {'duplicate_count': sum(bool(x.get('duplicate')) for x in items)})

    for run_number in (1, 2):
        started = time.perf_counter()
        status, result = request('/api/v1/ml/anomaly/run?limit=40', 'POST')
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        run_id = result.get('run_id')
        if run_id:
            run_ids.append(run_id)
            save_report()
        scored = result.get('top_anomalies', [])
        scores_ok = all(isinstance(x.get('anomaly_score'), (int, float)) and 0 <= x['anomaly_score'] <= 1 for x in scored)
        labels_ok = all(x.get('model_label') in ('baseline', 'anomaly_candidate') for x in scored)
        scored_ids = [x.get('event_id') for x in scored]
        check(f'ml_run_{run_number}_http_and_model_contract', status == 200 and result.get('model_name') == 'IsolationForest' and result.get('model_version') == 'aegis-iforest-v1' and result.get('training_mode') == 'unsupervised-on-recent-stored-events',
              {'http_status': status, 'model_name': result.get('model_name'), 'model_version': result.get('model_version'), 'training_mode': result.get('training_mode')})
        check(f'ml_run_{run_number}_sample_and_scoring_contract', result.get('sample_count') == 40 and result.get('feature_count', 0) > 0 and len(scored) == 25 and scores_ok and labels_ok and len(set(scored_ids)) == len(scored_ids),
              {'sample_count': result.get('sample_count'), 'feature_count': result.get('feature_count'), 'top_anomaly_count': len(scored), 'score_range_valid': scores_ok, 'labels_valid': labels_ok})
        check(f'ml_run_{run_number}_limitations_disclosed', len(result.get('limitations', [])) >= 3 and any('not maliciousness probabilities' in x for x in result.get('limitations', [])),
              {'limitations': result.get('limitations', [])})
        runs.append({'run_id': run_id, 'elapsed_ms': elapsed_ms, 'sample_count': result.get('sample_count'),
                     'feature_count': result.get('feature_count'), 'anomaly_candidate_count': result.get('anomaly_candidate_count'),
                     'top_event_ids': scored_ids})
        save_report()

    check('deterministic_repeatability', runs[0]['top_event_ids'] == runs[1]['top_event_ids'] and runs[0]['anomaly_candidate_count'] == runs[1]['anomaly_candidate_count'],
          {'run1_candidate_count': runs[0]['anomaly_candidate_count'], 'run2_candidate_count': runs[1]['anomaly_candidate_count'], 'top_ids_equal': runs[0]['top_event_ids'] == runs[1]['top_event_ids']})

    status, history = request('/api/v1/ml/anomaly/runs?limit=10')
    found = [x for x in history.get('items', []) if x.get('id') in run_ids]
    check('both_runs_persisted', status == 200 and len(found) == 2 and all(x.get('sample_count') == 40 for x in found),
          {'http_status': status, 'found_run_count': len(found), 'expected_run_ids': run_ids})

    status, audit = request('/api/v1/audit?limit=500')
    audit_found = [x for x in audit.get('items', []) if x.get('action') == 'ml.anomaly_run' and x.get('entity_id') in run_ids]
    check('both_ml_runs_audited', status == 200 and len(audit_found) == 2,
          {'http_status': status, 'audit_rows_found': len(audit_found)})

    save_report('PASS')
    print('\nReport:', REPORT)
    print('Status: PASS')
    print('Checks:', sum(x['status'] == 'PASS' for x in checks), '/', len(checks))
except Exception as exc:
    save_report('FAIL')
    print('\nAcceptance stopped:', type(exc).__name__, str(exc))
    print('Partial report saved for scoped cleanup:', REPORT)
    raise
