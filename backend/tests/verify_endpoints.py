from fastapi.testclient import TestClient
from app.main import app

def test_live_api_endpoints():
    client = TestClient(app)

    # 1. Test review code endpoint with Python snippet
    py_payload = {
        "code": "import subprocess\nsubprocess.run(['echo', 'hello'], shell=True)",
        "language": "python",
        "file_path": "test.py"
    }
    r1 = client.post("/api/v1/review/code", json=py_payload)
    assert r1.status_code == 200, f"Expected 200, got {r1.status_code}"
    data1 = r1.json()
    assert data1["count"] > 0, "Expected at least 1 review item"
    print("Python review test passed:", data1["reviews"][0]["title"])

    # 2. Test review code endpoint with JS snippet
    js_payload = {
        "code": "eval('2 + 2');",
        "language": "javascript",
        "file_path": "test.js"
    }
    r2 = client.post("/api/v1/review/code", json=js_payload)
    assert r2.status_code == 200
    data2 = r2.json()
    assert data2["count"] > 0, "Expected at least 1 review item for eval"
    print("JS review test passed:", data2["reviews"][0]["title"])

    # 3. Test lockfile parse endpoint with raw package.json
    pkg_payload = {
        "content": '{"dependencies": {"lodash": "^4.17.20", "express": "^4.18.2"}}',
        "filename": "package.json"
    }
    r3 = client.post("/api/v1/lockfile/parse", json=pkg_payload)
    assert r3.status_code == 200
    data3 = r3.json()
    assert data3["total_components"] == 2
    print("Lockfile parse test passed: 2 components extracted")

if __name__ == "__main__":
    test_live_api_endpoints()
    print("ALL LIVE ENDPOINT TESTS PASSED!")
