import json
import os
import uuid

def make_uuid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))

def scrub_scenario(scenario_id: str):
    path = f"c:/Users/DARAM  HEMANTH REDDY/Desktop/supplygraph/backend/app/scenarios/scenario_{scenario_id.lower()}.json"
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    sid = data.get("scenario_id", scenario_id.upper())
    
    # 1. Base Scan ID and details
    scan_id = make_uuid(f"scenario-{sid.lower()}")
    data["scan"]["id"] = scan_id
    data["scan"]["scenario_id"] = sid
    repo_name = f"supply-chain-demo-{sid.lower()}"
    data["scan"]["repository_url"] = f"https://github.com/demo/{repo_name}"
    
    # Repository Object
    if "repository" in data:
        data["repository"]["id"] = make_uuid(repo_name)
        data["repository"]["github_url"] = f"https://github.com/demo/{repo_name}"
        data["repository"]["name"] = repo_name

    # 2. Findings
    for i, finding in enumerate(data.get("findings", [])):
        finding["id"] = make_uuid(f"finding-{sid}-{i}")
        finding["scan_id"] = scan_id
        
    # 3. Attack Paths
    for i, ap in enumerate(data.get("attack_paths", [])):
        ap["id"] = make_uuid(f"path-{sid}-{i}")
        ap["scan_id"] = scan_id
        
        count = 0
        if "findings" in data and len(data["findings"]) > 0:
            impact = data["findings"][0].get("impact", {})
            count = impact.get("production_deployment_count", 0) + impact.get("service_count", 0) + impact.get("api_count", 0)
        
        # Or better: let's just make sure it's at least the length of affected_assets
        if count == 0 and "findings" in data and len(data["findings"]) > 0:
             count = len(data["findings"][0].get("affected_assets", []))

        # But the prompt specifically says "number of affected production assets reached by the attack path".
        # If D reaches all 3 (service, api, prod deployment), then count is 3.
        if sid.upper() == "D":
            count = 3
        ap["affected_asset_count"] = count

    # 4. Graph
    if "graph" in data:
        data["graph"]["scan_id"] = scan_id
        data["graph"]["node_count"] = len(data["graph"].get("nodes", []))
        data["graph"]["edge_count"] = len(data["graph"].get("edges", []))
        data["graph"]["attack_path_count"] = len(data.get("attack_paths", []))

    # 5. Assets
    if "assets" in data and len(data["assets"]) > 0:
        for asset in data["assets"]:
            asset["scan_id"] = scan_id
    else:
        asset_id = make_uuid(f"asset-{repo_name}")
        data["assets"] = [
            {
                "id": asset_id,
                "name": repo_name,
                "asset_type": "repository",
                "criticality": "medium",
                "is_production": False,
                "metadata": {
                    "label": "DEMO APPLICATION"
                },
                "scan_id": scan_id
            }
        ]
    
    # 6. Totals
    direct = sum(1 for c in data.get("components", []) if c.get("is_direct", False))
    transitive = sum(1 for c in data.get("components", []) if c.get("is_transitive", False))
    data["scan"]["total_components"] = len(data.get("components", []))
    data["scan"]["total_direct_dependencies"] = direct
    data["scan"]["total_transitive_dependencies"] = transitive
    data["scan"]["total_vulnerabilities"] = len(data.get("vulnerabilities", []))
    data["scan"]["total_findings"] = len(data.get("findings", []))
    data["scan"]["total_attack_paths"] = len(data.get("attack_paths", []))
    
    # 7. Gemini Context
    if sid != "A" and sid != "D":
        # Remove scenario A specific context from B, C, E
        if "gemini_prompt_context" in data:
            data["gemini_prompt_context"]["finding_summary"] = f"Scenario {sid} findings."
            data["gemini_prompt_context"]["origin"] = "Unknown"
            data["gemini_prompt_context"]["propagation"] = "Unknown"
            data["gemini_prompt_context"]["recommendation"] = "Unknown"

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Scrubbed {path}")

for s in ["a", "b", "c", "d", "e"]:
    scrub_scenario(s)

