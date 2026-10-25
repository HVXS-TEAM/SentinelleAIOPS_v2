"""Tests unitaires du socle d'API FastAPI."""
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_root_status():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["version"] == "2.0.0"

def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "securite" in data["modules"]
    assert "supervision" in data["modules"]
    assert "netdevops" in data["modules"]
    assert "parc" in data["modules"]
