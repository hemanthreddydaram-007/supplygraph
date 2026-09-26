import asyncio
import os
from dotenv import load_dotenv

# Load the token from the .env file we just created
load_dotenv()

from app.services.analysis_service import AnalysisService
from app.models.core import AnalysisRequest

async def main():
    svc = AnalysisService()
    
    repos = [
        "https://github.com/mtn6807/vulnerable",
        "https://github.com/chalk/chalk",
        "https://github.com/tastejs/todomvc",
        "https://github.com/nodeca/pako",
        "https://github.com/facebook/jest"
    ]
    
    for repo in repos:
        print(f"\n--- Testing {repo} ---")
        try:
            req = AnalysisRequest(github_url=repo, branch="master")
            try:
                res = await svc.run_analysis(req)
            except Exception as e:
                req = AnalysisRequest(github_url=repo, branch="main")
                res = await svc.run_analysis(req)
                
            print(f"Components: {len(res.components)}")
            print(f"Graph Nodes: {len(res.graph.nodes)}")
            print(f"Graph Edges: {len(res.graph.edges)}")
            print(f"Findings: {len(res.findings)}")
            print(f"Attack Paths: {len(res.attack_paths)}")
        except Exception as e:
            print(f"FAILED: {e}")

asyncio.run(main())
