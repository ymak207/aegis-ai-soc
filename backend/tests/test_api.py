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


def test_platform_catalog_covers_multiple_production_domains():
    response = client.get("/api/v1/platform/catalog")
    assert response.status_code == 200
    body = response.json()
    domain_ids = {item["id"] for item in body["domains"]}
    assert {"ecommerce", "telecom", "logistics", "cloud_saas", "financial_services"} <= domain_ids
    for domain in body["domains"]:
        assert domain["event_families"]
        assert domain["sources"]
        assert domain["required_context"]
        assert {"precision", "recall"} <= set(domain["evaluation_dimensions"])


def test_platform_catalog_is_honest_about_unimplemented_capabilities():
    response = client.get("/api/v1/platform/catalog")
    assert response.status_code == 200
    capabilities = {item["id"]: item for item in response.json()["capabilities"]}
    assert capabilities["rule_detection"]["status"] == "implemented"
    assert capabilities["a2a_acp"]["status"] == "planned"
    assert capabilities["ml_models"]["status"] == "planned"
    assert capabilities["mcp"]["status"] == "partial"
    assert all(item["evaluation"] for item in capabilities.values())


def test_platform_catalog_evaluation_principles_warn_against_cross_domain_scores():
    body = client.get("/api/v1/platform/catalog").json()
    principles = " ".join(body["evaluation_principles"]).lower()
    assert "across domains" in principles
    assert "false positives" in principles


def test_domain_rules_match_only_the_selected_domain():
    import app.main as main

    for domain, details in main.DOMAIN_CATALOG.items():
        family = details["event_families"][0]
        matches = main.domain_rule_matches({
            "event_type": family,
            "message": "synthetic domain signal",
            "raw": {"_aegis_domain": domain},
        })
        assert len(matches) == 1
        assert matches[0]["id"] == f"DOMAIN-{domain.upper()}-001"


def test_domain_rules_do_not_match_another_domains_event_family():
    import app.main as main

    assert main.domain_rule_matches({
        "event_type": "sim_swap",
        "message": "synthetic signal",
        "raw": {"_aegis_domain": "ecommerce"},
    }) == []


def test_domain_evaluation_is_explicitly_a_small_smoke_test():
    import app.main as main

    for domain in main.DOMAIN_CATALOG:
        result = main.score_domain_dataset(domain, main.DOMAIN_EVAL_DATASETS[domain])
        assert result["sample_count"] == 3
        assert result["dataset_version"] == f"aegis-{domain}-smoke-v1"
        assert result["evaluation_type"] == "synthetic-domain-rule-smoke-test"
        assert "not production detection validation" in " ".join(result["limitations"]).lower()


def test_domain_evaluation_api_rejects_unknown_domain():
    response = client.get("/api/v1/platform/domains/unknown/evaluation")
    assert response.status_code == 404


def test_event_domain_is_normalized_into_raw_context():
    event = normalized_event(EventIn(
        event_type="sim_swap",
        domain="telecom",
        message="synthetic SIM swap alert",
        source="unit-test",
        event_time="2026-01-01T00:00:00Z",
    ))
    assert event["raw"]["_aegis_domain"] == "telecom"
    assert any(rule["id"] == "DOMAIN-TELECOM-001" for rule in rule_matches(event))


def test_correlation_finds_domain_sequence_for_same_entity():
    from datetime import datetime, timezone
    import app.main as main

    events = [
        {"id": "e1", "event_time": datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
         "event_type": "account_takeover", "username": "synthetic-user",
         "raw": {"_aegis_domain": "ecommerce"}},
        {"id": "e2", "event_time": datetime(2026, 1, 1, 10, 12, tzinfo=timezone.utc),
         "event_type": "payment_abuse", "username": "synthetic-user",
         "raw": {"_aegis_domain": "ecommerce"}},
    ]

    leads = main.correlate_events(events)
    assert len(leads) == 1
    assert leads[0]["rule_id"] == "CORR-ECOM-001"
    assert leads[0]["evidence_event_ids"] == ["e1", "e2"]
    assert leads[0]["observed_interval_seconds"] == 720
    assert "do not prove causality" in " ".join(leads[0]["limitations"])


def test_correlation_rejects_different_entities_and_cross_domain_pairs():
    from datetime import datetime, timezone
    import app.main as main

    base_time = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        {"id": "e1", "event_time": base_time, "event_type": "sim_swap",
         "username": "user-a", "raw": {"_aegis_domain": "telecom"}},
        {"id": "e2", "event_time": base_time, "event_type": "subscriber_account_abuse",
         "username": "user-b", "raw": {"_aegis_domain": "telecom"}},
        {"id": "e3", "event_time": base_time, "event_type": "payment_abuse",
         "username": "user-a", "raw": {"_aegis_domain": "ecommerce"}},
    ]

    assert main.correlate_events(events) == []


def test_correlation_respects_time_window_and_event_order():
    from datetime import datetime, timedelta, timezone
    import app.main as main

    start = datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)
    events = [
        {"id": "late-trigger", "event_time": start + timedelta(minutes=31),
         "event_type": "credential_abuse", "username": "cloud-user",
         "raw": {"_aegis_domain": "cloud_saas"}},
        {"id": "too-late", "event_time": start + timedelta(minutes=62),
         "event_type": "privilege_escalation", "username": "cloud-user",
         "raw": {"_aegis_domain": "cloud_saas"}},
        {"id": "later-only", "event_time": start,
         "event_type": "transaction_abuse", "username": "finance-user",
         "raw": {"_aegis_domain": "financial_services"}},
    ]

    assert main.correlate_events(events) == []


def test_correlations_endpoint_rejects_unknown_domain_without_database_access():
    response = client.get("/api/v1/correlations?domain=unknown")
    assert response.status_code == 400
