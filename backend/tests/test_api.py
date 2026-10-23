from fastapi.testclient import TestClient

from app.main import app, normalized_event, rule_matches, EventIn

client = TestClient(app)


def test_liveness():
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"


def test_system_info_exposes_implemented_capabilities():
    response = client.get("/api/v1")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "AEGIS AI SOC"
    assert "rule-based-detection" in body["capabilities"]
    assert "case-management" in body["capabilities"]
    assert "threat-intelligence" in body["capabilities"]


def test_event_normalization_and_rule_match():
    event = normalized_event(EventIn(
        event_type="Authentication Failure",
        message="Invalid password",
        source="unit-test",
        event_time="2026-01-01T00:00:00Z",
    ))
    assert event["event_type"] == "authentication_failure"
    assert event["severity"] == "medium"
    assert rule_matches(event)[0]["id"] == "AUTH-001"


def test_suspicious_command_heuristic():
    event = normalized_event(EventIn(
        event_type="process_start",
        message="powershell -enc encoded-payload",
        event_time="2026-01-01T00:00:00Z",
    ))
    assert any(rule["id"] == "BEHAVIOR-001" for rule in rule_matches(event))


def test_metrics_is_prometheus_text_when_db_available():
    # DB-backed integration checks are exercised by the Compose verification script.
    response = client.get("/metrics")
    assert response.status_code in (200, 503)
    if response.status_code == 200:
        assert "aegis_events_total" in response.text



def test_mcp_initialize_and_tool_discovery():
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05"}})
    assert response.status_code == 200
    assert response.json()["result"]["serverInfo"]["name"] == "aegis-ai-soc"
    listed = client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()
    names = {item["name"] for item in listed["result"]["tools"]}
    assert {"get_overview", "search_alerts", "search_knowledge"} <= names


def test_mcp_rejects_unknown_tool_without_executing_anything():
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "run_shell", "arguments": {}}})
    assert response.status_code == 200
    assert response.json()["error"]["code"] == -32602


def test_mcp_rejects_invalid_json_rpc_method():
    response = client.post("/mcp", json={"jsonrpc": "2.0", "id": 4, "method": "not-a-method"})
    assert response.json()["error"]["code"] == -32601


def test_kafka_publisher_is_disabled_by_default(monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "KAFKA_ENABLED", False)
    assert main._publish_kafka_events([{"id": "synthetic-test"}]) == {"state": "disabled", "published": 0}


def test_vector_search_failure_is_a_safe_fallback(monkeypatch):
    import app.main as main
    monkeypatch.setattr(main, "_embed_text", lambda _text: (_ for _ in ()).throw(RuntimeError("model unavailable")))
    assert main._vector_search("authentication failures", 5) is None

def test_all_event_type_rule_groups():
    cases = [
        ("authentication_failure", "login failed", "AUTH-001"),
        ("failed_login", "invalid password", "AUTH-001"),
        ("threat_indicator_match", "synthetic IOC match", "NET-001"),
        ("suspicious_process", "unknown process", "ENDPOINT-001"),
        ("malware_detected", "synthetic malware alert", "ENDPOINT-001"),
        ("privilege_escalation", "privilege changed", "PRIV-001"),
    ]

    for event_type, message, expected_rule in cases:
        matches = rule_matches({
            "event_type": event_type,
            "message": message,
        })
        assert expected_rule in {rule["id"] for rule in matches}


def test_benign_message_without_suspicious_terms_does_not_match():
    matches = rule_matches({
        "event_type": "normal_activity",
        "message": "scheduled backup completed successfully",
    })

    assert matches == []


def test_command_heuristic_can_overlap_with_event_type_rule():
    matches = rule_matches({
        "event_type": "suspicious_process",
        "message": "mimikatz detected in synthetic simulation",
    })

    rule_ids = [rule["id"] for rule in matches]
    assert "ENDPOINT-001" in rule_ids
    assert "BEHAVIOR-001" in rule_ids


def test_detection_benchmark_v1_is_frozen_and_perfect_on_its_original_cases():
    import app.main as main

    result = main.score_detection_dataset(main.DETECTION_EVAL_DATASET_V1)
    assert len(main.DETECTION_EVAL_DATASET_V1) == 12
    assert result["confusion_matrix"] == {"tp": 8, "fp": 0, "tn": 4, "fn": 0}
    assert result["f1"] == 1.0


def test_detection_benchmark_v2_exposes_known_heuristic_errors():
    import app.main as main

    result = main.score_detection_dataset(main.DETECTION_EVAL_DATASET_V2)
    assert len(main.DETECTION_EVAL_DATASET_V2) == 8
    assert result["confusion_matrix"] == {"tp": 4, "fp": 1, "tn": 2, "fn": 1}
    assert result["precision"] == 0.8
    assert result["recall"] == 0.8
    assert result["accuracy"] == 0.75


def test_detection_benchmark_versions_have_distinct_immutable_labels():
    import app.main as main

    assert main.DETECTION_EVAL_DATASETS["v1"][0] == "aegis-synthetic-detection-v1"
    assert main.DETECTION_EVAL_DATASETS["v2"][0] == "aegis-synthetic-detection-v2"
    assert main.DETECTION_EVAL_DATASETS["v1"][1] is main.DETECTION_EVAL_DATASET_V1
    assert main.DETECTION_EVAL_DATASETS["v2"][1] is main.DETECTION_EVAL_DATASET_V2
