from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_liveness():
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "alive"

def test_system_info():
    response = client.get("/api/v1")
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "AEGIS AI SOC"
    assert "detection-and-alerts" in body["capabilities"]
