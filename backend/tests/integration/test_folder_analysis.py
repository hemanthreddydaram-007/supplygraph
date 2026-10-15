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


def test_analyze_folder_with_go_mod():
    go_mod = """module example.com/go-service
go 1.21
require (
    github.com/gin-gonic/gin v1.9.1
    golang.org/x/crypto v0.14.0 // indirect
)
"""
    payload = {
        "project_name": "Go Backend Service",
        "files": [
            {"path": "go.mod", "content": go_mod},
            {"path": "main.go", "content": "package main\nfunc main() {}"}
        ],
        "enable_code_review": False
    }
    response = client.post("/api/v1/analyze/folder", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan"]["status"] == "completed"
    assert data["scan"]["total_components"] >= 2
    comp_names = [c["name"] for c in data["components"]]
    assert "github.com/gin-gonic/gin" in comp_names
    assert "golang.org/x/crypto" in comp_names


def test_analyze_folder_with_cargo_manifests():
    cargo_lock = """version = 3
[[package]]
name = "tokio"
version = "1.35.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "serde"
version = "1.0.193"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    payload = {
        "project_name": "Rust Microservice",
        "files": [
            {"path": "Cargo.lock", "content": cargo_lock},
            {"path": "Cargo.toml", "content": "[package]\nname = \"rust-app\"\nversion = \"0.1.0\""}
        ],
        "enable_code_review": False
    }
    response = client.post("/api/v1/analyze/folder", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan"]["status"] == "completed"
    assert data["scan"]["total_components"] >= 2
    comp_names = [c["name"] for c in data["components"]]
    assert "tokio" in comp_names
    assert "serde" in comp_names

