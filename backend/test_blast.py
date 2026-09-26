import asyncio
from dotenv import load_dotenv

load_dotenv()

from app.services.analysis_service import AnalysisService
from app.models.core import AnalysisRequest

async def main():
    svc = AnalysisService()
    req = AnalysisRequest(github_url="https://github.com/mtn6807/vulnerable", branch="master")
    res = await svc.run_analysis(req)
    print("Total Findings:", len(res.findings))
    print("Scan Blast Radius:", res.scan.blast_radius_score)
    if res.findings:
        print("First finding impact:", res.findings[0].impact.blast_radius_score if res.findings[0].impact else None)

asyncio.run(main())
