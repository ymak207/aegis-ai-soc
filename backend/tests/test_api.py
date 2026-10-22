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
