import json
import uuid
import os
from datetime import datetime

def make_uuid(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, name))

def fix_scenario(filepath: str):
    with open(filepath, "r") as f:
        data = json.load(f)

    scan_id = make_uuid(data["scenario_id"])

    # 2. scan metadata
    if "scan" not in data or "repository_url" not in data["scan"]:
        repo_url = data.get("repository", {}).get("github_url", "https://github.com/demo/demo")
        data["scan"] = {
            "id": scan_id,
            "repository_id": make_uuid(data.get("repository", {}).get("id", "repo")),
            "repository_url": repo_url,
            "status": "completed",
            "scan_type": "demo",
            "scenario_id": data["scenario_id"],
            "started_at": datetime.utcnow().isoformat() + "Z",
            "completed_at": datetime.utcnow().isoformat() + "Z",
            "total_components": len(data.get("components", [])),
            "total_vulnerabilities": len(data.get("vulnerabilities", [])),
            "total_findings": len(data.get("findings", [])),
            "max_confidence": max([f.get("confidence", {}).get("score", 0) for f in data.get("findings", [])] + [0]),
            "blast_radius_score": sum(f.get("impact", {}).get("blast_radius_score", 0) for f in data.get("findings", []))
        }

    with open(filepath, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Fixed {filepath}")

base = r"c:\Users\DARAM  HEMANTH REDDY\Desktop\supplygraph\backend\app\scenarios"
fix_scenario(os.path.join(base, "scenario_a.json"))
fix_scenario(os.path.join(base, "scenario_d.json"))
