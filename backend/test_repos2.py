import asyncio
import os
from dotenv import load_dotenv

load_dotenv()

from app.services.analysis_service import AnalysisService
from app.models.core import AnalysisRequest
from app.services.github_service import GitHubService

async def main():
    svc = AnalysisService()
    gh = GitHubService()
    
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
            # fetch default branch dynamically
            gh_repo = gh.github.get_repo(gh._extract_repo_name(repo))
            default_branch = gh_repo.default_branch
            req = AnalysisRequest(github_url=repo, branch=default_branch)
            res = await svc.run_analysis(req)
                
            print(f"Branch: {default_branch}")
            print(f"Components: {len(res.components)}")
            print(f"Graph Nodes: {len(res.graph.nodes)}")
            print(f"Graph Edges: {len(res.graph.edges)}")
            print(f"Findings: {len(res.findings)}")
            print(f"Attack Paths: {len(res.attack_paths)}")
        except Exception as e:
            print(f"FAILED: {e}")

asyncio.run(main())
