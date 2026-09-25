import pytest
import httpx
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_scenario_a_b_isolation():
    # 1. Fetch Scenario A
    res_a = client.post("/api/v1/analyze/demo", json={"scenario_id": "A"})
    assert res_a.status_code == 200
    data_a = res_a.json()
    
    # 2. Fetch Scenario B
    res_b = client.post("/api/v1/analyze/demo", json={"scenario_id": "B"})
    assert res_b.status_code == 200
    data_b = res_b.json()
    
    # 3. Assert isolation
    assert data_a["scan"]["id"] != data_b["scan"]["id"], "Scan IDs must be completely isolated"
    
    # Check assets
    assert data_a["assets"][0]["id"] != data_b["assets"][0]["id"]
    assert data_a["assets"][0]["scan_id"] == data_a["scan"]["id"]
    assert data_b["assets"][0]["scan_id"] == data_b["scan"]["id"]
    assert data_a["assets"][0]["name"] == "supply-chain-demo-a"
    assert data_b["assets"][0]["name"] == "supply-chain-demo-b"
    
    # Check graph scan_id
    assert data_a["graph"]["scan_id"] == data_a["scan"]["id"]
    assert data_b["graph"]["scan_id"] == data_b["scan"]["id"]
    
    # Check findings scan_id
    for f in data_a["findings"]:
        assert f["scan_id"] == data_a["scan"]["id"]
        assert f["id"] not in [fb["id"] for fb in data_b["findings"]]
        
    for f in data_b["findings"]:
        assert f["scan_id"] == data_b["scan"]["id"]

def test_scenario_totals():
    for sid in ["A", "B", "C", "D", "E"]:
        res = client.post("/api/v1/analyze/demo", json={"scenario_id": sid})
        assert res.status_code == 200
        data = res.json()
        
        scan = data["scan"]
        
        direct = sum(1 for c in data.get("components", []) if c.get("is_direct", False))
        transitive = sum(1 for c in data.get("components", []) if c.get("is_transitive", False))
        
        assert scan["total_components"] == len(data.get("components", []))
        assert scan["total_direct_dependencies"] == direct
        assert scan["total_transitive_dependencies"] == transitive
        assert scan["total_vulnerabilities"] == len(data.get("vulnerabilities", []))
        assert scan["total_findings"] == len(data.get("findings", []))
        assert scan["total_attack_paths"] == len(data.get("attack_paths", []))
        assert data["graph"]["attack_path_count"] == len(data.get("attack_paths", []))
        assert data["graph"]["node_count"] == len(data["graph"]["nodes"])
        assert data["graph"]["edge_count"] == len(data["graph"]["edges"])

def test_scenario_d_affected_assets():
    res = client.post("/api/v1/analyze/demo", json={"scenario_id": "D"})
    assert res.status_code == 200
    data = res.json()
    
    finding = data["findings"][0]
    attack_path = data["attack_paths"][0]
    
    # Verify: 1. affected_asset_count equals the number of affected production assets reached by the attack path.
    # In D, 3 production assets are reached (service-x, api-gateway, production-deployment)
    assert attack_path["affected_asset_count"] == 3
    
    # Verify: 2. affected_assets in the finding is populated consistently
    assert len(finding["affected_assets"]) == 3
    
    # Verify: 3. The target_node_id production asset is included
    assert attack_path["target_node_id"] in finding["affected_assets"]
    
    # Verify: 4. blast radius calculation remains unchanged
    assert data["scan"]["blast_radius_score"] == 98.0
    assert attack_path["blast_radius"]["blast_radius_score"] == 98.0
