# Integration tests for Folder Upload & Code Review Endpoints
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_analyze_demo_returns_code_reviews():
    response = client.post("/api/v1/analyze/demo", json={"scenario_id": "A"})
    assert response.status_code == 200
    data = response.json()
    assert "code_reviews" in data
    assert len(data["code_reviews"]) >= 3
    for cr in data["code_reviews"]:
        assert "file_path" in cr
        assert "line_number" in cr
        assert "buggy_code" in cr
        assert "corrected_code" in cr
        assert len(cr["corrected_code"]) > 0


def test_analyze_folder_with_package_json_and_code():
    package_json = """{
  "name": "sample-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.20"
  }
}"""
    py_code = """import subprocess
def run_app():
    api_key = "super_secret_api_key_123"
    subprocess.run("ls", shell=True)
"""
    payload = {
        "project_name": "Test Upload Project",
        "files": [
            {"path": "package.json", "content": package_json},
            {"path": "app.py", "content": py_code}
        ],
        "enable_code_review": True
    }
    response = client.post("/api/v1/analyze/folder", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["api_version"] == "v1"
    assert data["scan"]["status"] == "completed"
    assert len(data["graph"]["nodes"]) > 0
    assert "code_reviews" in data
    assert len(data["code_reviews"]) >= 1


def test_review_code_snippet_endpoint():
    snippet = "const token = 'secret12345';\neval('2 + 2');\n"
    response = client.post("/api/v1/review/code", json={
        "code": snippet,
        "language": "javascript",
        "file_path": "test.js"
    })
    assert response.status_code == 200
    data = response.json()
    assert "reviews" in data
    assert len(data["reviews"]) >= 2
