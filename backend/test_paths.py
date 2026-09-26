import asyncio
from dotenv import load_dotenv

load_dotenv()

from app.services.analysis_service import AnalysisService
from app.models.core import AnalysisRequest

async def main():
    svc = AnalysisService()
    req = AnalysisRequest(github_url="https://github.com/mtn6807/vulnerable", branch="master")
    res = await svc.run_analysis(req)
    print("Vulnerable Findings:", len(res.findings))
    print("Attack Paths:", len(res.attack_paths))
    print("Blast Radius:", res.scan.blast_radius_score)

asyncio.run(main())
